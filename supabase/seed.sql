-- seed.sql — AuthorForge product catalog seed. Idempotent (ON CONFLICT DO NOTHING).

-- Product ------------------------------------------------------------------
insert into public.products (key, name, status)
values ('authorforge', 'AuthorForge', 'active')
on conflict (key) do nothing;

-- Release channels ---------------------------------------------------------
insert into public.release_channels (product_id, key, name)
select p.id, c.key, c.name
from public.products p
cross join (values ('stable','Stable'), ('beta','Beta')) as c(key, name)
where p.key = 'authorforge'
on conflict (product_id, key) do nothing;

-- Features -----------------------------------------------------------------
insert into public.features (key, value_type, description) values
  ('authorforge.cloud.enabled',         'boolean', 'Cloud features available'),
  ('authorforge.deep_analysis.enabled', 'boolean', 'Deep analysis available'),
  ('authorforge.devices.max',           'number',  'Maximum activated devices'),
  ('authorforge.updates.channel',       'string',  'Update channel'),
  ('authorforge.support.level',         'string',  'Support tier')
on conflict (key) do nothing;

-- Usage meters -------------------------------------------------------------
insert into public.usage_meters (key, unit, reset_cadence) values
  ('cloud_tokens',           'tokens',   'monthly'),
  ('deep_analysis_runs',     'runs',     'monthly'),
  ('premium_model_requests', 'requests', 'monthly'),
  ('cloud_storage_bytes',    'bytes',    'never')
on conflict (key) do nothing;

-- Plans --------------------------------------------------------------------
insert into public.plans (product_id, key, name, status)
select p.id, v.key, v.name, 'active'
from public.products p
cross join (values
  ('authorforge_included', 'AuthorForge Included'),
  ('authorforge_pro',      'AuthorForge Pro')
) as v(key, name)
where p.key = 'authorforge'
on conflict (product_id, key) do nothing;

-- Plan versions (v1 active for each) --------------------------------------
insert into public.plan_versions (plan_id, version, status, stripe_price_id)
select pl.id, 1, 'active',
       case when pl.key = 'authorforge_pro' then 'price_replace_me_pro' else null end
from public.plans pl
where pl.key in ('authorforge_included','authorforge_pro')
on conflict (plan_id, version) do nothing;

-- Plan features ------------------------------------------------------------
-- Included plan: cloud off, deep analysis off, 1 device, stable channel, community support
insert into public.plan_features (plan_version_id, feature_id, bool_value, number_value, string_value)
select pv.id, f.id, fv.bool_value, fv.number_value, fv.string_value
from public.plan_versions pv
join public.plans pl on pl.id = pv.plan_id and pl.key = 'authorforge_included'
join (values
  ('authorforge.cloud.enabled',         false, null::numeric, null::text),
  ('authorforge.deep_analysis.enabled', false, null,          null),
  ('authorforge.devices.max',           null,  1,             null),
  ('authorforge.updates.channel',       null,  null,          'stable'),
  ('authorforge.support.level',         null,  null,          'community')
) as fv(key, bool_value, number_value, string_value) on true
join public.features f on f.key = fv.key
on conflict (plan_version_id, feature_id) do nothing;

-- Pro plan: cloud on, deep analysis on, 3 devices, stable channel, priority support
insert into public.plan_features (plan_version_id, feature_id, bool_value, number_value, string_value)
select pv.id, f.id, fv.bool_value, fv.number_value, fv.string_value
from public.plan_versions pv
join public.plans pl on pl.id = pv.plan_id and pl.key = 'authorforge_pro'
join (values
  ('authorforge.cloud.enabled',         true,  null::numeric, null::text),
  ('authorforge.deep_analysis.enabled', true,  null,          null),
  ('authorforge.devices.max',           null,  3,             null),
  ('authorforge.updates.channel',       null,  null,          'stable'),
  ('authorforge.support.level',         null,  null,          'priority')
) as fv(key, bool_value, number_value, string_value) on true
join public.features f on f.key = fv.key
on conflict (plan_version_id, feature_id) do nothing;

-- Plan quotas --------------------------------------------------------------
-- Included plan: modest monthly cloud allowance.
insert into public.plan_quotas (plan_version_id, meter_key, limit_value, reset_cadence)
select pv.id, q.meter_key, q.limit_value, 'monthly'
from public.plan_versions pv
join public.plans pl on pl.id = pv.plan_id and pl.key = 'authorforge_included'
join (values
  ('cloud_tokens.monthly', 0),
  ('deep_analysis_runs.monthly', 0),
  ('premium_model_requests.monthly', 0)
) as q(meter_key, limit_value) on true
on conflict (plan_version_id, meter_key) do nothing;

-- Pro plan: generous monthly cloud allowance.
insert into public.plan_quotas (plan_version_id, meter_key, limit_value, reset_cadence)
select pv.id, q.meter_key, q.limit_value, 'monthly'
from public.plan_versions pv
join public.plans pl on pl.id = pv.plan_id and pl.key = 'authorforge_pro'
join (values
  ('cloud_tokens.monthly', 1000000),
  ('deep_analysis_runs.monthly', 500),
  ('premium_model_requests.monthly', 2000)
) as q(meter_key, limit_value) on true
on conflict (plan_version_id, meter_key) do nothing;

-- Policy versions ----------------------------------------------------------
insert into public.policy_versions (policy_key, version, url) values
  ('terms',   '2026-01-01', 'https://boswell.example/terms/2026-01-01'),
  ('privacy', '2026-01-01', 'https://boswell.example/privacy/2026-01-01')
on conflict (policy_key, version) do nothing;
