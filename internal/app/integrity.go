package app

import (
	"log/slog"
	"peak-auth/internal/util"

	"gorm.io/gorm"
)

// VerifySystemIntegrity comprueba que los componentes y filas fundamentales
// del sistema existan y estén activos en la base de datos tras las migraciones.
func VerifySystemIntegrity(db *gorm.DB) {
	if db == nil {
		slog.Warn("Integrity check omitido: instancia de base de datos no inicializada")
		return
	}

	checks := []struct {
		Name  string
		Query string
		Args  []any
	}{
		{
			Name:  "Aplicación raíz (peak-auth)",
			Query: "SELECT COUNT(*) FROM applications WHERE app_id = ? AND is_active = true AND deleted_at IS NULL",
			Args:  []any{util.AppIdPeakAuth},
		},
		{
			Name:  "Rol del sistema ROOT",
			Query: "SELECT COUNT(*) FROM roles WHERE name = ? AND is_default = true AND deleted_at IS NULL",
			Args:  []any{"ROOT"},
		},
		{
			Name:  "Rol del sistema OWNER",
			Query: "SELECT COUNT(*) FROM roles WHERE name = ? AND is_default = true AND deleted_at IS NULL",
			Args:  []any{"OWNER"},
		},
		{
			Name:  "Rol del sistema ADMIN",
			Query: "SELECT COUNT(*) FROM roles WHERE name = ? AND is_default = true AND deleted_at IS NULL",
			Args:  []any{"ADMIN"},
		},
		{
			Name:  "Rol del sistema USER",
			Query: "SELECT COUNT(*) FROM roles WHERE name = ? AND is_default = true AND deleted_at IS NULL",
			Args:  []any{"USER"},
		},
	}

	for _, c := range checks {
		var count int64
		if err := db.Raw(c.Query, c.Args...).Scan(&count).Error; err != nil {
			slog.Warn("No se pudo ejecutar chequeo de integridad", "componente", c.Name, "error", err)
			continue
		}
		if count == 0 {
			slog.Warn("⚠️ ADVERTENCIA DE INTEGRIDAD: Componente crítico ausente o inactivo",
				"componente", c.Name,
				"detalle", "Si es la primera ejecución del sistema, se creará durante el Setup inicial.",
			)
		}
	}
}
