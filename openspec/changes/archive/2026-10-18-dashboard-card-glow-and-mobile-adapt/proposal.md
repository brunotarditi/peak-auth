# Proposal

## Why

El panel principal (dashboard) de Peak Auth muestra las aplicaciones registradas con un diseño que, si bien es limpio, resulta estático y algo aislado en pantallas amplias cuando hay pocos clientes registrados. Además, la experiencia en dispositivos móviles y pantallas táctiles requiere optimizaciones de espaciado, áreas de toque mínimas (touch targets >= 44px) y consistencia en el lenguaje visual (Sentence Case y micro-interacciones suaves). Esta mejora introduce un efecto visual distintivo y sobrio ("Halo Sentinel" o iluminación perimetral sutil infinita en las tarjetas de aplicación), refuerza la jerarquía visual de acciones y optimiza el comportamiento responsivo en navegadores móviles sin agregar librerías externas ni comprometer el rendimiento.

## What Changes

- **Efecto de Iluminación Perimetral Continua ("Halo Sentinel")**: Animación sutil con `conic-gradient` o haz perimetral continuo en los bordes de `.app-card-item`, manteniendo el estilo visual sobrio de developer platform sin caer en estética gamer/neón estridente.
- **Soporte para Accesibilidad y Reducción de Movimiento**: Inclusión de `@media (prefers-reduced-motion: reduce)` para pausar la animación o reemplazarla por un borde con acento estático y refinado.
- **Micro-interacciones y Estados Hover/Active**: Elevación suave, sombra con tinte sutil del color de acento y feedback táctil (`:active`) optimizado en mobile.
- **Tipografía y UX Writing en Sentence Case**: Estandarización de textos y botones de acción (por ejemplo, "Configuración" y "Usuarios" en vez de mayúsculas fijas agresivas o Title Case anglosajón).
- **Optimización y Auditoría Mobile**:
  - Garantizar áreas táctiles mínimas de 44x44px en botones, enlaces y menús desplegables.
  - Ajuste de padding del layout principal en viewports estrechos (< 640px) para evitar desbordes y mejorar la legibilidad.
  - Comportamiento fluido de las cards en grid/flexbox mobile-first.

## Capabilities

### New Capabilities
- `admin-ui/dashboard-cards`: Especifica el comportamiento visual, animaciones perimetrales continuas, accesibilidad a nivel de movimiento y estados de interacción de las tarjetas de aplicaciones en el dashboard administrativo.
- `admin-ui/mobile-viewport`: Especifica las pautas responsivas, dimensiones táctiles mínimas y adaptaciones de layout para navegación móvil en la consola de administración.

### Modified Capabilities
<!-- No existing capabilities yet -->

## Impact

- **Frontend CSS**: Modificaciones en `web/static/css/components.css` (estilos de cards, keyframes de iluminación, media queries) y `web/static/css/layout.css` (padding mobile).
- **Plantillas HTML**: Ajustes menores en `web/templates/admin/dashboard.html` para clases, micro-copia y consistencia Sentence Case.
- **Rendimiento y Dependencias**: 0 dependencias añadidas (100% Vanilla CSS). Utilización de `transform` y pseudo-elementos acelerados por GPU sin provocar re-flows ni alterar la semántica de accesibilidad.
