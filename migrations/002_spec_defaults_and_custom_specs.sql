-- Migration 002: Add default specification values and custom offer item specification fields
ALTER TABLE specification_keys
  ADD COLUMN IF NOT EXISTS default_value TEXT;

ALTER TABLE specification_options
  ADD COLUMN IF NOT EXISTS is_default BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE offer_item_specifications
  ALTER COLUMN specification_key_id DROP NOT NULL;

ALTER TABLE offer_item_specifications
  ADD COLUMN IF NOT EXISTS custom_key_name TEXT,
  ADD COLUMN IF NOT EXISTS custom_price_modifier DECIMAL(10, 2) DEFAULT 0.00;
