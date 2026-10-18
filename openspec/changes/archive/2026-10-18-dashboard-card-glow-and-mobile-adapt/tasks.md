# Tasks

## 1. Halo Sentinel Border Animation & Card Styling

- [x] 1.1 Implementar la estructura CSS para el borde animado infinito "Halo Sentinel" en `.app-card-item` (`web/static/css/components.css`) usando conic-gradient y pseudo-elementos, verificando que la animación gire suavemente y sin bloquear el layout.
- [x] 1.2 Agregar soporte `@media (prefers-reduced-motion: reduce)` en `components.css`, verificando que la animación se detenga y se muestre un borde estático refinado cuando esté activo.
- [x] 1.3 Refinar estados de hover y active (`transform: translateY(-2px)`, sombras profundas con acento sutil) para escritorio y móvil en `components.css`.

## 2. Dashboard Template & Sentence Case Copy

- [x] 2.1 Actualizar `web/templates/admin/dashboard.html` para unificar los textos de botones ("Configuración", "Usuarios") y badges en español Sentence Case.
- [x] 2.2 Agregar contador contextual de aplicaciones en el encabezado del dashboard ("1 aplicación" / "X aplicaciones").

## 3. Mobile Ergonomics & Viewport Audit

- [x] 3.1 Auditar y ajustar tamaños táctiles (touch targets >= 44px de alto) en botones `.btn-card-action` y enlaces clave en `web/static/css/components.css` y `web/static/css/layout.css`.
- [x] 3.2 Ajustar padding y márgenes de contenedor en viewports <= 640px para asegurar lectura ergonómica y eliminar cualquier riesgo de desborde horizontal.

## 4. Verification & Testing

- [x] 4.1 Ejecutar `go test ./...` y `go build -v .` para verificar que la compilación de Go y todos los tests existentes pasen al 100%.
- [x] 4.2 Validar el estado del cambio con `openspec validate` asegurando que todos los requisitos y tareas cumplan la especificación.

## Workflow follow-up

- Archivar el cambio en OpenSpec una vez verificado.
