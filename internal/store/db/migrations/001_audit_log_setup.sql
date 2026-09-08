-- 001_audit_log_setup.sql
-- Crea la tabla de auditoría central y la función genérica del trigger con sanitización de secretos

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    schema_name VARCHAR(100) NOT NULL,
    table_name VARCHAR(100) NOT NULL,
    record_id TEXT,                              -- ID del registro afectado (para búsquedas directas e indexadas)
    action VARCHAR(10) NOT NULL,                 -- INSERT, UPDATE, DELETE
    changed_by TEXT,                             -- Usuario de la app (app.current_user) o usuario de conexión BD
    old_data JSONB,                              -- Estado previo del registro (sin secretos ni contraseñas)
    new_data JSONB,                              -- Estado nuevo del registro (sin secretos ni contraseñas)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Índices B-Tree optimizados para consultas habituales y orden cronológico
-- NOTA: idx_audit_logs_record ya cubre búsquedas por table_name como prefijo izquierdo
CREATE INDEX IF NOT EXISTS idx_audit_logs_record ON audit_logs(table_name, record_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);

-- Función del trigger que inyectará los datos automáticamente en audit_logs de forma segura
CREATE OR REPLACE FUNCTION log_changes()
RETURNS TRIGGER 
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_old_data JSONB;
    v_new_data JSONB;
    v_record_id TEXT;
    v_changed_by TEXT;
BEGIN
    -- 1. Determinar quién realizó la acción (prioriza variable de sesión de la app, fallback al usuario de BD)
    v_changed_by := COALESCE(NULLIF(current_setting('app.current_user', true), ''), SESSION_USER);

    -- 2. Determinar el record_id según la operación
    IF TG_OP = 'DELETE' THEN
        v_record_id := (to_jsonb(OLD) ->> 'id');
    ELSE
        v_record_id := (to_jsonb(NEW) ->> 'id');
    END IF;

    -- 3. Sanitizar payload nuevo (INSERT / UPDATE)
    IF TG_OP IN ('INSERT', 'UPDATE') THEN
        v_new_data := to_jsonb(NEW) 
                      - 'password' - 'password_hash' - 'salt'
                      - 'secret_key' - 'secret' - 'client_secret'
                      - 'code_hash' - 'token' - 'token_hash' - 'code' - 'access_token' - 'refresh_token'
                      - 'api_key' - 'private_key' - 'otp_secret';
    END IF;

    -- 4. Sanitizar payload previo (UPDATE / DELETE)
    IF TG_OP IN ('UPDATE', 'DELETE') THEN
        v_old_data := to_jsonb(OLD) 
                      - 'password' - 'password_hash' - 'salt'
                      - 'secret_key' - 'secret' - 'client_secret'
                      - 'code_hash' - 'token' - 'token_hash' - 'code' - 'access_token' - 'refresh_token'
                      - 'api_key' - 'private_key' - 'otp_secret';
    END IF;

    -- 5. Inserción en tabla audit_logs
    IF TG_OP = 'INSERT' THEN
        INSERT INTO audit_logs (schema_name, table_name, record_id, action, changed_by, new_data)
        VALUES (TG_TABLE_SCHEMA, TG_TABLE_NAME, v_record_id, 'INSERT', v_changed_by, v_new_data);
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO audit_logs (schema_name, table_name, record_id, action, changed_by, old_data, new_data)
        VALUES (TG_TABLE_SCHEMA, TG_TABLE_NAME, v_record_id, 'UPDATE', v_changed_by, v_old_data, v_new_data);
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO audit_logs (schema_name, table_name, record_id, action, changed_by, old_data)
        VALUES (TG_TABLE_SCHEMA, TG_TABLE_NAME, v_record_id, 'DELETE', v_changed_by, v_old_data);
        RETURN OLD;
    END IF;

    RETURN NULL;
END;
$$;
