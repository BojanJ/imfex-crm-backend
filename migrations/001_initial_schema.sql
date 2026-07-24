-- IMFEX Multi-Specification CRM & PDF Offer Engine Schema Migration
-- Database: PostgreSQL / Supabase

-- 1. Create Custom ENUM Types
CREATE TYPE user_role AS ENUM ('SUPER_ADMIN', 'USER');
CREATE TYPE spec_input_type AS ENUM ('SELECT', 'MULTISELECT', 'TEXT', 'NUMBER');
CREATE TYPE customer_type AS ENUM ('INDIVIDUAL', 'COMPANY', 'PARTNER', 'OTHER');
CREATE TYPE offer_status AS ENUM ('DRAFT', 'SENT', 'ACCEPTED', 'REJECTED');

-- 2. Profiles Table (Extends Supabase auth.users)
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    full_name TEXT,
    role user_role NOT NULL DEFAULT 'USER',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. Products Table
CREATE TABLE IF NOT EXISTS public.products (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    code TEXT UNIQUE NOT NULL,
    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 4. Product Models Table
CREATE TABLE IF NOT EXISTS public.product_models (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id UUID NOT NULL REFERENCES public.products(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    base_price DECIMAL(10,2) NOT NULL DEFAULT 0.00,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 5. Specification Keys Table
CREATE TABLE IF NOT EXISTS public.specification_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id UUID NOT NULL REFERENCES public.products(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    input_type spec_input_type NOT NULL DEFAULT 'SELECT',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 6. Specification Options Table
CREATE TABLE IF NOT EXISTS public.specification_options (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    specification_key_id UUID NOT NULL REFERENCES public.specification_keys(id) ON DELETE CASCADE,
    label TEXT NOT NULL,
    price_modifier DECIMAL(10,2) NOT NULL DEFAULT 0.00,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 7. Customers Table
CREATE TABLE IF NOT EXISTS public.customers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_type customer_type NOT NULL DEFAULT 'INDIVIDUAL',
    name TEXT NOT NULL,
    company_name TEXT,
    tax_id TEXT,
    email TEXT,
    phone TEXT,
    address TEXT,
    city TEXT,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 8. Offer Sequence Generator for Offer Number (OFF-YYYY-0001)
CREATE SEQUENCE IF NOT EXISTS offer_number_seq START WITH 1;

CREATE OR REPLACE FUNCTION generate_offer_number()
RETURNS TRIGGER AS $$
DECLARE
    current_year TEXT;
    seq_val INT;
BEGIN
    current_year := TO_CHAR(NOW(), 'YYYY');
    seq_val := NEXTVAL('offer_number_seq');
    NEW.offer_number := 'OFF-' || current_year || '-' || LPAD(seq_val::TEXT, 4, '0');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 9. Offers Table
CREATE TABLE IF NOT EXISTS public.offers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    offer_number TEXT UNIQUE,
    customer_id UUID NOT NULL REFERENCES public.customers(id) ON DELETE CASCADE,
    created_by_user_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    status offer_status NOT NULL DEFAULT 'DRAFT',
    tax_rate DECIMAL(5,2) NOT NULL DEFAULT 18.00,
    subtotal DECIMAL(10,2) NOT NULL DEFAULT 0.00,
    tax_amount DECIMAL(10,2) NOT NULL DEFAULT 0.00,
    total_amount DECIMAL(10,2) NOT NULL DEFAULT 0.00,
    valid_until DATE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER trigger_set_offer_number
BEFORE INSERT ON public.offers
FOR EACH ROW
WHEN (NEW.offer_number IS NULL OR NEW.offer_number = '')
EXECUTE FUNCTION generate_offer_number();

-- 10. Offer Items Table
CREATE TABLE IF NOT EXISTS public.offer_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    offer_id UUID NOT NULL REFERENCES public.offers(id) ON DELETE CASCADE,
    service_types TEXT[] NOT NULL DEFAULT '{}',
    product_id UUID REFERENCES public.products(id) ON DELETE SET NULL,
    product_model_id UUID REFERENCES public.product_models(id) ON DELETE SET NULL,
    custom_title TEXT,
    width_mm INT,
    height_mm INT,
    quantity INT NOT NULL DEFAULT 1,
    unit_price DECIMAL(10,2) NOT NULL DEFAULT 0.00,
    total_price DECIMAL(10,2) NOT NULL DEFAULT 0.00,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 11. Offer Item Specifications Table
CREATE TABLE IF NOT EXISTS public.offer_item_specifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    offer_item_id UUID NOT NULL REFERENCES public.offer_items(id) ON DELETE CASCADE,
    specification_key_id UUID NOT NULL REFERENCES public.specification_keys(id) ON DELETE CASCADE,
    specification_option_id UUID REFERENCES public.specification_options(id) ON DELETE CASCADE,
    custom_value TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -------------------------------------------------------------
-- ROW LEVEL SECURITY (RLS) POLICIES
-- -------------------------------------------------------------
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.products ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.product_models ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.specification_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.specification_options ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.offers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.offer_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.offer_item_specifications ENABLE ROW LEVEL SECURITY;

-- Helper function to check if user is SUPER_ADMIN
CREATE OR REPLACE FUNCTION public.is_super_admin()
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM public.profiles
        WHERE id = auth.uid() AND role = 'SUPER_ADMIN'
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Products RLS: Everyone read, Super Admin full CRUD
CREATE POLICY "Public read products" ON public.products FOR SELECT USING (true);
CREATE POLICY "Super admin modify products" ON public.products FOR ALL USING (public.is_super_admin());

-- Product Models RLS
CREATE POLICY "Public read product_models" ON public.product_models FOR SELECT USING (true);
CREATE POLICY "Super admin modify product_models" ON public.product_models FOR ALL USING (public.is_super_admin());

-- Specification Keys & Options RLS
CREATE POLICY "Public read specification_keys" ON public.specification_keys FOR SELECT USING (true);
CREATE POLICY "Super admin modify specification_keys" ON public.specification_keys FOR ALL USING (public.is_super_admin());

CREATE POLICY "Public read specification_options" ON public.specification_options FOR SELECT USING (true);
CREATE POLICY "Super admin modify specification_options" ON public.specification_options FOR ALL USING (public.is_super_admin());

-- Customers & Offers RLS: Authenticated users can read/write
CREATE POLICY "Authenticated full access to customers" ON public.customers FOR ALL USING (auth.role() = 'authenticated');
CREATE POLICY "Authenticated full access to offers" ON public.offers FOR ALL USING (auth.role() = 'authenticated');
CREATE POLICY "Authenticated full access to offer_items" ON public.offer_items FOR ALL USING (auth.role() = 'authenticated');
CREATE POLICY "Authenticated full access to offer_item_specifications" ON public.offer_item_specifications FOR ALL USING (auth.role() = 'authenticated');
