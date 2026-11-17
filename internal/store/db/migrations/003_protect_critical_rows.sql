-- 003_protect_critical_rows.sql
-- Triggers BEFORE que impiden eliminación o manipulación de filas vitales del sistema.

-- 1. Proteger la aplicación raíz ('peak-auth')
CREATE OR REPLACE FUNCTION protect_root_app()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF TG_OP = 'DELETE' AND OLD.app_id = 'peak-auth' THEN
        RAISE EXCEPTION 'BLOCKED: No se puede eliminar la aplicación raíz del sistema (peak-auth)';
    END IF;

    IF TG_OP = 'UPDATE' AND OLD.app_id = 'peak-auth' THEN
        IF NEW.is_active = false THEN
            RAISE EXCEPTION 'BLOCKED: No se puede desactivar la aplicación raíz del sistema (peak-auth)';
        END IF;

        IF NEW.app_id != 'peak-auth' THEN
            RAISE EXCEPTION 'BLOCKED: No se puede modificar el app_id de la aplicación raíz';
        END IF;
    END IF;

    RETURN COALESCE(NEW, OLD);
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_protect_root_app') THEN
        CREATE TRIGGER trg_protect_root_app
        BEFORE UPDATE OR DELETE ON public.applications
        FOR EACH ROW EXECUTE FUNCTION protect_root_app();
    END IF;
END;
$$;

-- 2. Proteger los roles protegidos del sistema (is_default = true)
CREATE OR REPLACE FUNCTION protect_default_roles()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF OLD.is_default = true THEN
        RAISE EXCEPTION 'BLOCKED: No se puede eliminar el rol protegido del sistema "%"', OLD.name;
    END IF;
    RETURN OLD;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_protect_default_roles') THEN
        CREATE TRIGGER trg_protect_default_roles
        BEFORE DELETE ON public.roles
        FOR EACH ROW EXECUTE FUNCTION protect_default_roles();
    END IF;
END;
$$;

-- 3. Proteger las reglas maestras de la aplicación raíz
CREATE OR REPLACE FUNCTION protect_root_app_rules()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_app_id TEXT;
BEGIN
    SELECT app_id INTO v_app_id FROM public.applications WHERE id = OLD.application_id;
    IF v_app_id = 'peak-auth' THEN
        RAISE EXCEPTION 'BLOCKED: No se pueden eliminar reglas maestras de la aplicación raíz (peak-auth)';
    END IF;
    RETURN OLD;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_protect_root_app_rules') THEN
        CREATE TRIGGER trg_protect_root_app_rules
        BEFORE DELETE ON public.application_rules
        FOR EACH ROW EXECUTE FUNCTION protect_root_app_rules();
    END IF;
END;
$$;
