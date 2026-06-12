//! Licensing persistence: installation registration, license activation with device-limit
//! enforcement, heartbeat, deactivation, read-own listings, and the license sync applied
//! when verified subscription truth changes.
//!
//! Every privileged mutation runs in a transaction with its audit (and, where the event
//! contract defines one, outbox) write. Activation locks the license row so concurrent
//! activations cannot oversubscribe the device limit.

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::domain::installation::ValidatedRegistration;
use crate::domain::license::{
    can_activate_device, license_sync_action, LicenseStatus, LicenseSyncAction,
};
use crate::domain::redaction::sanitize;
use crate::domain::subscription::SubscriptionStatus;

#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    #[error("unknown or inactive product")]
    UnknownProduct,
    #[error("install key already registered for a different product")]
    ProductMismatch,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum ActivationError {
    #[error("installation not found")]
    InstallationNotFound,
    #[error("installation is deactivated")]
    InstallationDeactivated,
    #[error("license not found")]
    LicenseNotFound,
    #[error("no active license for this product")]
    NoActiveLicense,
    #[error("license is not active ({0})")]
    LicenseNotActive(String),
    #[error("activation blocked by an explicit revocation")]
    RevocationBlocked,
    #[error("device limit reached ({active_devices}/{device_limit})")]
    DeviceLimitReached {
        device_limit: u32,
        active_devices: u32,
    },
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// Installation projection returned to the owning customer.
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct InstallationRow {
    pub id: Uuid,
    pub fleet_id: Option<Uuid>,
    pub install_key: String,
    pub product_key: String,
    pub app_version: Option<String>,
    pub build_id: Option<String>,
    pub platform: Option<String>,
    pub architecture: Option<String>,
    pub package_format: Option<String>,
    pub updater_version: Option<String>,
    pub status: String,
    pub device_id: Option<Uuid>,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct RegisteredInstallation {
    pub installation: InstallationRow,
    pub created: bool,
    pub reactivated: bool,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct DeviceRow {
    pub id: Uuid,
    pub public_key: String,
    pub public_key_fpr: String,
    pub label: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct LicenseRow {
    pub id: Uuid,
    pub product_key: String,
    pub status: String,
    pub device_limit: i32,
    pub active_devices: i64,
    pub subscription_id: Option<Uuid>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct ActivationOutcome {
    pub activation_id: Uuid,
    pub license_id: Uuid,
    pub installation_id: Uuid,
    pub activated_at: DateTime<Utc>,
    pub device_limit: u32,
    pub active_devices: u32,
    pub already_active: bool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct HeartbeatRow {
    pub id: Uuid,
    pub status: String,
    pub app_version: Option<String>,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct DeactivationOutcome {
    pub installation_id: Uuid,
    pub status: String,
    pub released_activations: u64,
    pub already_deactivated: bool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct InstallationContextRow {
    id: Uuid,
    status: String,
    device_id: Option<Uuid>,
    product_id: Uuid,
    device_status: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct LicenseLockRow {
    id: Uuid,
    status: String,
    device_limit: i32,
    expires_at: Option<DateTime<Utc>>,
}

/// Register (or idempotently return) an installation by client-supplied install key.
/// Re-registering a deactivated installation reactivates the installation record itself —
/// license slots are only consumed by activation. First registration emits the sanitized
/// `installation_registered` outbox event.
pub async fn register_installation(
    pool: &PgPool,
    customer_id: Uuid,
    input: &ValidatedRegistration,
) -> Result<RegisteredInstallation, RegistrationError> {
    let mut tx = pool.begin().await?;

    let product = sqlx::query_as::<_, (Uuid, String)>(
        "select id, key from public.products where key = $1 and status = 'active'",
    )
    .bind(&input.product_key)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(RegistrationError::UnknownProduct)?;

    let device_id = match &input.device {
        Some(device) => Some(
            sqlx::query_scalar::<_, Uuid>(
                r#"
                insert into public.devices (customer_id, public_key, public_key_fpr, label)
                values ($1, $2, $3, $4)
                on conflict (customer_id, public_key_fpr) do update
                    set label = coalesce(excluded.label, devices.label)
                returning id
                "#,
            )
            .bind(customer_id)
            .bind(&device.public_key)
            .bind(&device.public_key_fpr)
            .bind(device.label.as_deref())
            .fetch_one(&mut *tx)
            .await?,
        ),
        None => None,
    };

    let fleet_id = sqlx::query_scalar::<_, Uuid>(
        r#"
        with inserted as (
          insert into public.fleets (customer_id, display_name, fleet_type, status, update_ring, release_channel_id)
          values (
            $1,
            'Default fleet',
            'default',
            'active',
            'standard',
            (
              select rc.id
              from public.release_channels rc
              join public.products p on p.id = rc.product_id
              where p.key = $2 and rc.key = 'stable'
              limit 1
            )
          )
          on conflict do nothing
          returning id
        )
        select id from inserted
        union all
        select id from public.fleets
        where customer_id = $1 and fleet_type = 'default' and status <> 'deleted'
        limit 1
        "#,
    )
    .bind(customer_id)
    .bind(&product.1)
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        insert into public.fleet_applications (fleet_id, product_id, status, update_ring, release_channel_id)
        values (
          $1,
          $2,
          'active',
          'standard',
          (select rc.id from public.release_channels rc
           where rc.product_id = $2 and rc.key = 'stable' limit 1)
        )
        on conflict (fleet_id, product_id) do nothing
        "#,
    )
    .bind(fleet_id)
    .bind(product.0)
    .execute(&mut *tx)
    .await?;

    let inserted = sqlx::query_as::<_, InstallationRow>(
        r#"
        insert into public.installations
            (customer_id, device_id, fleet_id, install_key, product_id, app_version,
             build_id, platform, architecture, package_format, updater_version)
        values
            ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        on conflict (customer_id, install_key) do nothing
        returning id, fleet_id, install_key, $12::text as product_key, app_version, build_id,
                  platform, architecture, package_format, updater_version, status, device_id,
                  last_heartbeat_at, created_at
        "#,
    )
    .bind(customer_id)
    .bind(device_id)
    .bind(fleet_id)
    .bind(&input.install_key)
    .bind(product.0)
    .bind(input.app_version.as_deref())
    .bind(input.build_id.as_deref())
    .bind(input.platform.as_deref())
    .bind(input.architecture.as_deref())
    .bind(input.package_format.as_deref())
    .bind(input.updater_version.as_deref())
    .bind(&product.1)
    .fetch_optional(&mut *tx)
    .await?;

    let registered = match inserted {
        Some(installation) => {
            write_outbox(
                &mut tx,
                "installation_registered",
                format!("installation_registered:{}", installation.id),
                json!({
                    "customer_id": customer_id,
                    "installation_id": installation.id,
                    "fleet_id": installation.fleet_id,
                    "product": product.1,
                    "has_device": device_id.is_some(),
                    "occurred_at": Utc::now(),
                }),
            )
            .await?;
            RegisteredInstallation {
                installation,
                created: true,
                reactivated: false,
            }
        }
        None => {
            let prior = sqlx::query_as::<_, (Uuid, String, Uuid)>(
                r#"
                select id, status, product_id from public.installations
                where customer_id = $1 and install_key = $2
                for update
                "#,
            )
            .bind(customer_id)
            .bind(&input.install_key)
            .fetch_one(&mut *tx)
            .await?;
            if prior.2 != product.0 {
                return Err(RegistrationError::ProductMismatch);
            }

            let installation = sqlx::query_as::<_, InstallationRow>(
                r#"
                update public.installations
                set status = 'active',
                    app_version = coalesce($2, app_version),
                    device_id = coalesce($3, device_id),
                    fleet_id = coalesce(fleet_id, $5),
                    build_id = coalesce($6, build_id),
                    platform = coalesce($7, platform),
                    architecture = coalesce($8, architecture),
                    package_format = coalesce($9, package_format),
                    updater_version = coalesce($10, updater_version)
                where id = $1
                returning id, fleet_id, install_key, $4::text as product_key, app_version,
                          build_id, platform, architecture, package_format, updater_version,
                          status, device_id, last_heartbeat_at, created_at
                "#,
            )
            .bind(prior.0)
            .bind(input.app_version.as_deref())
            .bind(device_id)
            .bind(&product.1)
            .bind(fleet_id)
            .bind(input.build_id.as_deref())
            .bind(input.platform.as_deref())
            .bind(input.architecture.as_deref())
            .bind(input.package_format.as_deref())
            .bind(input.updater_version.as_deref())
            .fetch_one(&mut *tx)
            .await?;
            RegisteredInstallation {
                installation,
                created: false,
                reactivated: prior.1 == "deactivated",
            }
        }
    };

    tx.commit().await?;
    Ok(registered)
}

/// Activate a license on an installation, enforcing the device limit and explicit
/// revocations. Idempotent for an already-active (license, installation) pair. The
/// license row is locked for the duration so concurrent activations serialize.
pub async fn activate_installation(
    pool: &PgPool,
    customer_id: Uuid,
    installation_id: Uuid,
    license_id: Option<Uuid>,
    correlation_id: Option<&str>,
) -> Result<ActivationOutcome, ActivationError> {
    let mut tx = pool.begin().await?;

    let installation = sqlx::query_as::<_, InstallationContextRow>(
        r#"
        select i.id, i.status, i.device_id, i.product_id, d.status as device_status
        from public.installations i
        left join public.devices d on d.id = i.device_id
        where i.id = $1 and i.customer_id = $2
        "#,
    )
    .bind(installation_id)
    .bind(customer_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ActivationError::InstallationNotFound)?;
    if installation.status == "deactivated" {
        return Err(ActivationError::InstallationDeactivated);
    }
    if installation.device_status.as_deref() == Some("revoked") {
        return Err(ActivationError::RevocationBlocked);
    }

    let license = match license_id {
        Some(license_id) => sqlx::query_as::<_, LicenseLockRow>(
            r#"
            select id, status, device_limit, expires_at from public.licenses
            where id = $1 and customer_id = $2
            for update
            "#,
        )
        .bind(license_id)
        .bind(customer_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ActivationError::LicenseNotFound)?,
        None => sqlx::query_as::<_, LicenseLockRow>(
            r#"
            select id, status, device_limit, expires_at from public.licenses
            where customer_id = $1
              and product_id = $2
              and status = 'active'
              and (expires_at is null or expires_at > now())
            order by issued_at desc
            limit 1
            for update
            "#,
        )
        .bind(customer_id)
        .bind(installation.product_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ActivationError::NoActiveLicense)?,
    };

    if license.status == "revoked" {
        return Err(ActivationError::RevocationBlocked);
    }
    if license.status != "active" {
        return Err(ActivationError::LicenseNotActive(license.status));
    }
    if matches!(license.expires_at, Some(expires_at) if expires_at <= Utc::now()) {
        return Err(ActivationError::LicenseNotActive("expired".to_string()));
    }

    // Explicit denial records block silent reactivation: a revocation scoped to the whole
    // license, to this installation, or to this device denies activation.
    let revocation_blocked = sqlx::query_scalar::<_, bool>(
        r#"
        select exists (
            select 1 from public.license_revocations r
            where (r.license_id = $1 and r.installation_id is null and r.device_id is null)
               or r.installation_id = $2
               or ($3::uuid is not null and r.device_id = $3)
        )
        "#,
    )
    .bind(license.id)
    .bind(installation.id)
    .bind(installation.device_id)
    .fetch_one(&mut *tx)
    .await?;
    if revocation_blocked {
        return Err(ActivationError::RevocationBlocked);
    }

    let device_limit = u32::try_from(license.device_limit.max(0)).unwrap_or(0);
    let active_count = sqlx::query_scalar::<_, i64>(
        "select count(*) from public.license_activations where license_id = $1 and status = 'active'",
    )
    .bind(license.id)
    .fetch_one(&mut *tx)
    .await?;
    let active_devices = u32::try_from(active_count.max(0)).unwrap_or(u32::MAX);

    let existing = sqlx::query_as::<_, (Uuid, DateTime<Utc>)>(
        r#"
        select id, activated_at from public.license_activations
        where license_id = $1 and installation_id = $2 and status = 'active'
        "#,
    )
    .bind(license.id)
    .bind(installation.id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((activation_id, activated_at)) = existing {
        tx.commit().await?;
        return Ok(ActivationOutcome {
            activation_id,
            license_id: license.id,
            installation_id: installation.id,
            activated_at,
            device_limit,
            active_devices,
            already_active: true,
        });
    }

    if !can_activate_device(active_devices, device_limit) {
        return Err(ActivationError::DeviceLimitReached {
            device_limit,
            active_devices,
        });
    }

    let (activation_id, activated_at) = sqlx::query_as::<_, (Uuid, DateTime<Utc>)>(
        r#"
        insert into public.license_activations (license_id, installation_id, device_id)
        values ($1, $2, $3)
        returning id, activated_at
        "#,
    )
    .bind(license.id)
    .bind(installation.id)
    .bind(installation.device_id)
    .fetch_one(&mut *tx)
    .await?;

    write_customer_audit(
        &mut tx,
        CustomerAudit {
            event_type: "license_activated",
            customer_id,
            target_type: "license_activation",
            target_id: activation_id.to_string(),
            reason: "installation_activate",
            before_state: None,
            after_state: Some(json!({
                "license_id": license.id,
                "installation_id": installation.id,
                "device_id": installation.device_id,
                "active_devices": active_devices + 1,
                "device_limit": device_limit,
            })),
            correlation_id,
        },
    )
    .await?;
    write_outbox(
        &mut tx,
        "license_activated",
        format!("license_activated:{activation_id}"),
        json!({
            "customer_id": customer_id,
            "license_id": license.id,
            "installation_id": installation.id,
            "device_id": installation.device_id,
            "active_devices": active_devices + 1,
            "device_limit": device_limit,
            "occurred_at": activated_at,
        }),
    )
    .await?;

    tx.commit().await?;
    Ok(ActivationOutcome {
        activation_id,
        license_id: license.id,
        installation_id: installation.id,
        activated_at,
        device_limit,
        active_devices: active_devices + 1,
        already_active: false,
    })
}

/// Record liveness for an installation; optionally refreshes the reported app version.
pub async fn heartbeat_installation(
    pool: &PgPool,
    customer_id: Uuid,
    installation_id: Uuid,
    app_version: Option<&str>,
) -> Result<Option<HeartbeatRow>, sqlx::Error> {
    sqlx::query_as::<_, HeartbeatRow>(
        r#"
        update public.installations
        set last_heartbeat_at = now(),
            app_version = coalesce($3, app_version)
        where id = $1 and customer_id = $2
        returning id, status, app_version, last_heartbeat_at
        "#,
    )
    .bind(installation_id)
    .bind(customer_id)
    .bind(app_version)
    .fetch_optional(pool)
    .await
}

/// Deactivate an installation and release its active license activations (freeing device
/// slots). Idempotent: an already-deactivated installation is reported as such.
pub async fn deactivate_installation(
    pool: &PgPool,
    customer_id: Uuid,
    installation_id: Uuid,
    correlation_id: Option<&str>,
) -> Result<DeactivationOutcome, ActivationError> {
    let mut tx = pool.begin().await?;

    let status = sqlx::query_scalar::<_, String>(
        r#"
        select status from public.installations
        where id = $1 and customer_id = $2
        for update
        "#,
    )
    .bind(installation_id)
    .bind(customer_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ActivationError::InstallationNotFound)?;
    if status == "deactivated" {
        tx.commit().await?;
        return Ok(DeactivationOutcome {
            installation_id,
            status,
            released_activations: 0,
            already_deactivated: true,
        });
    }

    sqlx::query("update public.installations set status = 'deactivated' where id = $1")
        .bind(installation_id)
        .execute(&mut *tx)
        .await?;
    let released = sqlx::query(
        r#"
        update public.license_activations
        set status = 'deactivated', deactivated_at = now()
        where installation_id = $1 and status = 'active'
        "#,
    )
    .bind(installation_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    write_customer_audit(
        &mut tx,
        CustomerAudit {
            event_type: "installation_deactivated",
            customer_id,
            target_type: "installation",
            target_id: installation_id.to_string(),
            reason: "installation_deactivate",
            before_state: Some(json!({ "status": "active" })),
            after_state: Some(json!({
                "status": "deactivated",
                "released_activations": released,
            })),
            correlation_id,
        },
    )
    .await?;

    tx.commit().await?;
    Ok(DeactivationOutcome {
        installation_id,
        status: "deactivated".to_string(),
        released_activations: released,
        already_deactivated: false,
    })
}

pub async fn list_installations(
    pool: &PgPool,
    customer_id: Uuid,
) -> Result<Vec<InstallationRow>, sqlx::Error> {
    sqlx::query_as::<_, InstallationRow>(
        r#"
        select i.id, i.fleet_id, i.install_key, p.key as product_key, i.app_version,
               i.build_id, i.platform, i.architecture, i.package_format, i.updater_version,
               i.status, i.device_id, i.last_heartbeat_at, i.created_at
        from public.installations i
        join public.products p on p.id = i.product_id
        where i.customer_id = $1
        order by i.created_at
        "#,
    )
    .bind(customer_id)
    .fetch_all(pool)
    .await
}

pub async fn list_devices(pool: &PgPool, customer_id: Uuid) -> Result<Vec<DeviceRow>, sqlx::Error> {
    sqlx::query_as::<_, DeviceRow>(
        r#"
        select id, public_key, public_key_fpr, label, status, created_at
        from public.devices
        where customer_id = $1
        order by created_at
        "#,
    )
    .bind(customer_id)
    .fetch_all(pool)
    .await
}

pub async fn list_licenses(
    pool: &PgPool,
    customer_id: Uuid,
) -> Result<Vec<LicenseRow>, sqlx::Error> {
    sqlx::query_as::<_, LicenseRow>(
        r#"
        select l.id, p.key as product_key, l.status, l.device_limit,
               (select count(*) from public.license_activations a
                where a.license_id = l.id and a.status = 'active') as active_devices,
               l.subscription_id, l.issued_at, l.expires_at
        from public.licenses l
        join public.products p on p.id = l.product_id
        where l.customer_id = $1
        order by l.issued_at desc
        "#,
    )
    .bind(customer_id)
    .fetch_all(pool)
    .await
}

/// Result of syncing a subscription-linked license, for the caller's audit write.
#[derive(Debug, Clone)]
pub struct LicenseSyncOutcome {
    pub license_id: Uuid,
    pub before_status: Option<String>,
    pub before_device_limit: Option<i32>,
    pub after_status: String,
    pub device_limit: i32,
    audit_event_type: &'static str,
}

impl LicenseSyncOutcome {
    pub fn audit_event_type(&self) -> &'static str {
        self.audit_event_type
    }

    pub fn before_state(&self) -> Option<Value> {
        self.before_status.as_ref().map(|status| {
            json!({
                "license_status": status,
                "device_limit": self.before_device_limit,
            })
        })
    }

    pub fn after_state(&self) -> Value {
        json!({
            "license_status": self.after_status,
            "device_limit": self.device_limit,
        })
    }
}

/// Keep the license linked to a subscription consistent with verified subscription truth.
/// Issues on first grant, suspends/expires/reactivates per the pure transition rules, and
/// refreshes the device limit from the (possibly new) plan version while the subscription
/// is in good standing. Must run inside the webhook-processing transaction; the caller is
/// responsible for the audit write.
pub async fn sync_license_for_subscription(
    tx: &mut Transaction<'_, Postgres>,
    customer_id: Uuid,
    subscription_id: Uuid,
    plan_version_id: Uuid,
    subscription_status: SubscriptionStatus,
) -> Result<Option<LicenseSyncOutcome>, sqlx::Error> {
    let Some((product_id, devices_max)) = sqlx::query_as::<_, (Uuid, Option<i64>)>(
        r#"
        select pl.product_id,
               (select floor(pf.number_value)::int8
                from public.plan_features pf
                join public.features f on f.id = pf.feature_id
                where pf.plan_version_id = pv.id
                  and f.key = p.key || '.devices.max') as devices_max
        from public.plan_versions pv
        join public.plans pl on pl.id = pv.plan_id
        join public.products p on p.id = pl.product_id
        where pv.id = $1
        "#,
    )
    .bind(plan_version_id)
    .fetch_optional(&mut **tx)
    .await?
    else {
        return Ok(None);
    };
    // Plans without an explicit devices.max feature default to a single device.
    let device_limit =
        i32::try_from(devices_max.unwrap_or(1).clamp(0, i64::from(i32::MAX))).unwrap_or(1);

    let existing = sqlx::query_as::<_, (Uuid, String, i32)>(
        r#"
        select id, status, device_limit from public.licenses
        where customer_id = $1 and subscription_id = $2
        for update
        "#,
    )
    .bind(customer_id)
    .bind(subscription_id)
    .fetch_optional(&mut **tx)
    .await?;

    let action = license_sync_action(
        existing
            .as_ref()
            .map(|(_, status, _)| LicenseStatus::parse(status)),
        subscription_status,
    );

    let outcome = match (existing, action) {
        (None, Some(LicenseSyncAction::Issue)) => {
            let license_id = sqlx::query_scalar::<_, Uuid>(
                r#"
                insert into public.licenses
                    (customer_id, product_id, subscription_id, status, device_limit)
                values
                    ($1, $2, $3, 'active', $4)
                returning id
                "#,
            )
            .bind(customer_id)
            .bind(product_id)
            .bind(subscription_id)
            .bind(device_limit)
            .fetch_one(&mut **tx)
            .await?;
            Some(LicenseSyncOutcome {
                license_id,
                before_status: None,
                before_device_limit: None,
                after_status: "active".to_string(),
                device_limit,
                audit_event_type: "license_issued",
            })
        }
        (Some((license_id, status, old_limit)), Some(LicenseSyncAction::Reactivate)) => {
            sqlx::query(
                r#"
                update public.licenses
                set status = 'active', device_limit = $2, expires_at = null
                where id = $1
                "#,
            )
            .bind(license_id)
            .bind(device_limit)
            .execute(&mut **tx)
            .await?;
            Some(LicenseSyncOutcome {
                license_id,
                before_status: Some(status),
                before_device_limit: Some(old_limit),
                after_status: "active".to_string(),
                device_limit,
                audit_event_type: "license_reactivated",
            })
        }
        (Some((license_id, status, old_limit)), Some(LicenseSyncAction::Suspend)) => {
            sqlx::query("update public.licenses set status = 'suspended' where id = $1")
                .bind(license_id)
                .execute(&mut **tx)
                .await?;
            Some(LicenseSyncOutcome {
                license_id,
                before_status: Some(status),
                before_device_limit: Some(old_limit),
                after_status: "suspended".to_string(),
                device_limit: old_limit,
                audit_event_type: "license_suspended",
            })
        }
        (Some((license_id, status, old_limit)), Some(LicenseSyncAction::Expire)) => {
            sqlx::query(
                r#"
                update public.licenses
                set status = 'expired', expires_at = coalesce(expires_at, now())
                where id = $1
                "#,
            )
            .bind(license_id)
            .execute(&mut **tx)
            .await?;
            Some(LicenseSyncOutcome {
                license_id,
                before_status: Some(status),
                before_device_limit: Some(old_limit),
                after_status: "expired".to_string(),
                device_limit: old_limit,
                audit_event_type: "license_expired",
            })
        }
        // Plan change while in good standing: refresh the device limit in place.
        (Some((license_id, status, old_limit)), None)
            if status == "active"
                && subscription_status.grants_cloud()
                && old_limit != device_limit =>
        {
            sqlx::query("update public.licenses set device_limit = $2 where id = $1")
                .bind(license_id)
                .bind(device_limit)
                .execute(&mut **tx)
                .await?;
            Some(LicenseSyncOutcome {
                license_id,
                before_status: Some(status),
                before_device_limit: Some(old_limit),
                after_status: "active".to_string(),
                device_limit,
                audit_event_type: "license_device_limit_changed",
            })
        }
        _ => None,
    };

    Ok(outcome)
}

/// Customer-actor audit record, shared by the licensing and entitlement repositories.
pub(crate) struct CustomerAudit<'a> {
    pub(crate) event_type: &'a str,
    pub(crate) customer_id: Uuid,
    pub(crate) target_type: &'a str,
    pub(crate) target_id: String,
    pub(crate) reason: &'a str,
    pub(crate) before_state: Option<Value>,
    pub(crate) after_state: Option<Value>,
    pub(crate) correlation_id: Option<&'a str>,
}

pub(crate) async fn write_customer_audit(
    tx: &mut Transaction<'_, Postgres>,
    record: CustomerAudit<'_>,
) -> Result<(), sqlx::Error> {
    let before_state = record.before_state.map(|value| sanitize(&value));
    let after_state = record.after_state.map(|value| sanitize(&value));
    sqlx::query(
        r#"
        insert into public.commercial_audit_events
            (event_type, actor_type, actor_id, customer_id, target_type, target_id, reason,
             before_state, after_state, correlation_id)
        values
            ($1, 'customer', $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(record.event_type)
    .bind(record.customer_id.to_string())
    .bind(record.customer_id)
    .bind(record.target_type)
    .bind(record.target_id)
    .bind(record.reason)
    .bind(before_state)
    .bind(after_state)
    .bind(record.correlation_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Sanitized outbox insert, shared by the licensing/admin repositories.
pub(crate) async fn write_outbox(
    tx: &mut Transaction<'_, Postgres>,
    event_type: &str,
    delivery_key: String,
    payload: Value,
) -> Result<(), sqlx::Error> {
    let payload = sanitize(&payload);
    sqlx::query(
        r#"
        insert into public.outbox_events (event_type, delivery_key, payload)
        values ($1, $2, $3)
        on conflict (delivery_key) do nothing
        "#,
    )
    .bind(event_type)
    .bind(delivery_key)
    .bind(payload)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
