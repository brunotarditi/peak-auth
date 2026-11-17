-- 004_audit_triggers_sensitive.sql
-- Conecta el trigger log_changes() a las tablas con datos sensibles restantes.

DO $$
BEGIN
    -- Tabla: public.refresh_tokens
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_audit_refresh_tokens') THEN
        CREATE TRIGGER trg_audit_refresh_tokens
        AFTER INSERT OR UPDATE OR DELETE ON public.refresh_tokens
        FOR EACH ROW EXECUTE FUNCTION log_changes();
    END IF;

    -- Tabla: public.user_mfa_credentials
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_audit_user_mfa_credentials') THEN
        CREATE TRIGGER trg_audit_user_mfa_credentials
        AFTER INSERT OR UPDATE OR DELETE ON public.user_mfa_credentials
        FOR EACH ROW EXECUTE FUNCTION log_changes();
    END IF;

    -- Tabla: public.user_recovery_codes
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_audit_user_recovery_codes') THEN
        CREATE TRIGGER trg_audit_user_recovery_codes
        AFTER INSERT OR UPDATE OR DELETE ON public.user_recovery_codes
        FOR EACH ROW EXECUTE FUNCTION log_changes();
    END IF;

    -- Tabla: public.user_identities
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_audit_user_identities') THEN
        CREATE TRIGGER trg_audit_user_identities
        AFTER INSERT OR UPDATE OR DELETE ON public.user_identities
        FOR EACH ROW EXECUTE FUNCTION log_changes();
    END IF;
END;
$$;
