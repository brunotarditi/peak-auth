-- 002_audit_triggers.sql
-- Conecta el trigger log_changes a las tablas más sensibles del sistema

DO $$
BEGIN
    -- Tabla: public.users
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_audit_users') THEN
        CREATE TRIGGER trg_audit_users
        AFTER INSERT OR UPDATE OR DELETE ON public.users
        FOR EACH ROW EXECUTE FUNCTION log_changes();
    END IF;

    -- Tabla: public.roles
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_audit_roles') THEN
        CREATE TRIGGER trg_audit_roles
        AFTER INSERT OR UPDATE OR DELETE ON public.roles
        FOR EACH ROW EXECUTE FUNCTION log_changes();
    END IF;

    -- Tabla: public.applications
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_audit_applications') THEN
        CREATE TRIGGER trg_audit_applications
        AFTER INSERT OR UPDATE OR DELETE ON public.applications
        FOR EACH ROW EXECUTE FUNCTION log_changes();
    END IF;

    -- Tabla: public.application_rules
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_audit_application_rules') THEN
        CREATE TRIGGER trg_audit_application_rules
        AFTER INSERT OR UPDATE OR DELETE ON public.application_rules
        FOR EACH ROW EXECUTE FUNCTION log_changes();
    END IF;

    -- Tabla: public.user_application_roles
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_audit_user_application_roles') THEN
        CREATE TRIGGER trg_audit_user_application_roles
        AFTER INSERT OR UPDATE OR DELETE ON public.user_application_roles
        FOR EACH ROW EXECUTE FUNCTION log_changes();
    END IF;
END;
$$;
