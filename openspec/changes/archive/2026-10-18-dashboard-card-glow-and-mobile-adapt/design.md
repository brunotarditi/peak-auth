# Design

## Context

El dashboard de administración de Peak Auth (`web/templates/admin/dashboard.html`) renderiza las tarjetas de aplicación utilizando clases definidas en `web/static/css/components.css` y `web/static/css/layout.css`. La arquitectura visual está basada estrictamente en **Vanilla CSS** con variables de diseño semánticas (`web/static/css/variables.css`), sin dependencias de Tailwind ni JavaScript para animaciones cosméticas.

## Goals / Non-Goals

**Goals:**
- Implementar el efecto "Halo Sentinel" (iluminación perimetral infinita y sobria) puramente mediante CSS moderno (pseudo-elementos `::before`/`::after` o `background` con `conic-gradient`), optimizado para renderizado por GPU.
- Garantizar accesibilidad total respetando `prefers-reduced-motion: reduce`.
- Adecuar el layout y las tarjetas a estándares ergonómicos móviles (touch targets de al menos 44px de alto, padding responsivo en pantallas de menos de 640px).
- Refinar textos a Sentence Case ("Configuración", "Usuarios") y mejorar la jerarquía visual de la tarjeta de aplicación.

**Non-Goals:**
- No implementar widgets ni paneles laterales de tips/métricas ficticias que sobrecarguen el MVP o no aporten datos reales.
- No alterar endpoints ni modelos del backend Go en este cambio.
- No utilizar librerías externas de CSS ni JavaScript adicional para las animaciones.

## Decisions

### 1. Animación perimetral mediante CSS Conic-Gradient y Pseudo-elementos
- **Decisión**: Utilizar un contenedor de tarjeta `.app-card-item` con `position: relative`, `overflow: hidden`, y un pseudo-elemento `::before` rotando suavemente con `conic-gradient(from 0deg, transparent 0%, var(--brand-500) 25%, transparent 50%, var(--brand-400) 75%, transparent 100%)`. El contenido interior se aloja sobre una capa superior con fondo `var(--bg-surface)` y margen/padding de 1px a 1.5px para simular el borde perimetral iluminado.
- **Alternativas consideradas**:
  - *Box-shadow animado pulsante*: Consume más recursos de pintado y genera una sensación tosca o de "neón estático".
  - *SVG animado con stroke-dashoffset*: Aumenta la complejidad del HTML e impacta en el mantenimiento de plantillas.
- **Razón**: El conic gradient con `transform: rotate()` se procesa íntegramente en el compositor de la GPU, garantizando 60fps fluidos tanto en escritorio como en navegadores móviles.

### 2. Soporte estricto de Reducción de Movimiento
- **Decisión**: Emplear `@media (prefers-reduced-motion: reduce)` para anular `animation: none` en el pseudo-elemento y proveer un borde sutil estático con `border: 1px solid var(--border-color)`.

### 3. Ergonomía Móvil y Touch Targets
- **Decisión**: Para viewports `<= 640px` y punteros táctiles (`@media (pointer: coarse)`), asegurar que los botones de acción (`.btn-card-action`, botones de menú) tengan una altura mínima de 44px, espaciado táctil y feedback `:active` con ligera compresión (`transform: scale(0.98)`).

## Risks / Trade-offs

- [Consumo de batería en dispositivos móviles] → Mitigado utilizando opacidades muy suaves, aceleración de composición (`will-change: transform` contenido) y posibilidad de que en pantallas muy reducidas el halo sea más sutil o estático si el usuario tiene batería baja/modo ahorro de energía.
- [Compatibilidad de `conic-gradient`] → Los navegadores modernos (Chrome 69+, Safari 12.1+, Firefox 75+) tienen 100% de soporte nativo. Para navegadores obsoletos hay fallback natural a `border: 1px solid var(--border-color)`.
