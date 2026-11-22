---
name: Peak Auth
description: Sistema de Autenticación SSO & Proveedor de Identidad Empresarial
colors:
  cobalt-primary: "#2563eb"
  cobalt-hover: "#1d4ed8"
  cobalt-soft-bg: "#eff6ff"
  cobalt-soft-border: "#bfdbfe"
  slate-body-light: "#f8fafc"
  slate-surface-light: "#ffffff"
  slate-border-light: "#e2e8f0"
  slate-text-main: "#0f172a"
  slate-text-muted: "#64748b"
  slate-text-light: "#94a3b8"
  slate-body-dark: "#020617"
  slate-surface-dark: "#0f172a"
  slate-surface-hover-dark: "#1e293b"
  slate-border-dark: "#334155"
  emerald-status: "#10b981"
  emerald-text: "#047857"
  amber-status: "#f59e0b"
  amber-text: "#b45309"
  rose-status: "#e11d48"
  rose-soft-bg: "#fff1f2"
typography:
  display:
    fontFamily: "Inter, system-ui, -apple-system, sans-serif"
    fontSize: "1.75rem"
    fontWeight: 800
    lineHeight: 1.2
    letterSpacing: "-0.025em"
  headline:
    fontFamily: "Inter, system-ui, -apple-system, sans-serif"
    fontSize: "1.25rem"
    fontWeight: 800
    lineHeight: 1.3
    letterSpacing: "-0.025em"
  title:
    fontFamily: "Inter, system-ui, -apple-system, sans-serif"
    fontSize: "1rem"
    fontWeight: 700
    lineHeight: 1.4
    letterSpacing: "normal"
  body:
    fontFamily: "Inter, system-ui, -apple-system, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 500
    lineHeight: 1.5
    letterSpacing: "normal"
  label:
    fontFamily: "Inter, system-ui, -apple-system, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 700
    lineHeight: 1.4
    letterSpacing: "0.1em"
rounded:
  sm: "0.125rem"
  md: "0.375rem"
  lg: "0.5rem"
  xl: "0.75rem"
  2xl: "1rem"
  full: "9999px"
spacing:
  xs: "0.25rem"
  sm: "0.5rem"
  md: "1rem"
  lg: "1.5rem"
  xl: "2rem"
  2xl: "2.5rem"
components:
  button-primary:
    backgroundColor: "{colors.cobalt-primary}"
    textColor: "{colors.slate-surface-light}"
    rounded: "{rounded.xl}"
    padding: "0.75rem 1.5rem"
  button-primary-hover:
    backgroundColor: "{colors.cobalt-hover}"
  button-secondary:
    backgroundColor: "{colors.slate-body-light}"
    textColor: "{colors.slate-text-muted}"
    rounded: "{rounded.xl}"
    padding: "0.75rem 1.5rem"
  input-field:
    backgroundColor: "{colors.slate-surface-light}"
    textColor: "{colors.slate-text-main}"
    rounded: "{rounded.xl}"
    padding: "0.75rem 1.25rem"
  card-container:
    backgroundColor: "{colors.slate-surface-light}"
    rounded: "{rounded.2xl}"
    padding: "2rem"
---

# Design System: Peak Auth

## Overview

**Creative North Star: "The Sovereign Sentinel"**

Peak Auth proyecta la sobriedad, precisión y temple inquebrantable de una estación de control criptográfica moderna. Su lenguaje visual rechaza los artificios decorativos, los degradados inflados y las ilustraciones superfluas de los productos SaaS genéricos. En su lugar, abraza una arquitectura de información estructurada, bordes nítidos de 1 píxel y una jerarquía tipográfica rigurosa orientada a la toma de decisiones técnicas sin fatiga cognitiva.

Cada superficie está construida para operar con naturalidad en entornos críticos: desde consolas de administración para ingenieros de plataformas hasta pantallas de inicio de sesión Single Sign-On limpias y confiables para usuarios finales. El sistema equilibra fondos tonales reposados con acentos de cobalto quirúrgicamente dosificados, reforzando la sensación de seguridad verificable y estabilidad operativa en modos claro y oscuro.

**Key Characteristics:**
- Estructura sobria con límites perimetrales definidos mediante bordes sutiles de 1 píxel.
- Acentos cobalto reservados exclusivamente para intenciones primarias y anillos de foco.
- Tipografía técnica y legible en Inter con espaciado óptico y densidad balanceada.
- Modos claro y oscuro con calibración tonal profunda (pizarra neutra `#020617` a `#f8fafc`).
- Redacción y microcopy en español respetando estrictamente el formato Sentence Case.

## Colors

La paleta cromática se organiza en un eje neutro de pizarra de alto contraste respaldado por un acento primario cobalto de precisión y semáforos de estado inequívocos.

### Primary
- **Cobalt Precision Blue** (#2563eb / `--brand-600`): Color insignia del sistema, reservado para llamadas a la acción principales, estados activos y confirmaciones críticas.
- **Cobalt Deep Hover** (#1d4ed8 / `--brand-700`): Respuesta interactiva al posar el cursor sobre elementos primarios.
- **Cobalt Soft Tint** (#eff6ff / `--brand-50`): Fondos de soporte para insignias informativas y botones sutiles en modo claro.

### Neutral
- **Deep Obsidian Void** (#020617 / `--slate-950`): Fondo principal inmersivo para el modo oscuro (`--bg-body`).
- **Surface Slate** (#0f172a / `--slate-900`): Superficie de tarjetas y contenedores en modo oscuro, y texto principal en modo claro (`--text-main`).
- **Structural Border Slate** (#e2e8f0 / `--slate-200` y #334155 / `--slate-700`): Límites perimetrales de 1px entre tarjetas, tablas y entradas.
- **Muted Slate** (#64748b / `--slate-500`): Etiquetas secundarias, metadatos, iconos inactivos y textos auxiliares.
- **Crystalline Light Body** (#f8fafc / `--slate-50`): Lienzo de fondo en modo claro.
- **Pure White Surface** (#ffffff / `--white`): Fondo de tarjetas y paneles en modo claro.

### Semantic / Status
- **Status Emerald** (#10b981 / `--emerald-500`): Indicador de éxito, estados activos, sesiones vigentes y validaciones correctas.
- **Warning Amber** (#f59e0b / `--amber-500`): Alertas de expiración próxima, políticas pendientes y advertencias de auditoría.
- **Rose Barrier** (#e11d48 / `--rose-600`): Acciones destructivas, errores de autenticación, revocaciones y advertencias críticas.

### Named Rules
**The 10% Cobalt Rule.** El cobalto primario jamás debe superar el 10% del área visible de cualquier pantalla. Su efectividad radica en su rareza visual como guía inequívoca de acción.  
**The Dual-Signal Status Rule.** Todo estado crítico (éxito, advertencia o peligro) debe comunicar su condición simultáneamente mediante color semántico y un indicador geométrico o icono explicativo.

## Typography

**Display Font:** Inter (`system-ui, -apple-system, sans-serif`)  
**Body Font:** Inter (`system-ui, -apple-system, sans-serif`)  
**Label/Mono Font:** Inter / Mono de sistema para identificadores técnicos, hashes y tokens (`monospace`)

**Character:** Tipografía geométrica humanista con excelente legibilidad en pantalla, números tabulares claros y peso visual contundente en encabezados.

### Hierarchy
- **Display** (800, 1.75rem / 28px, line-height 1.2, letter-spacing -0.025em): Títulos de vistas principales de autenticación y encabezados de página de administración.
- **Headline** (800, 1.25rem / 20px, line-height 1.3, letter-spacing -0.025em): Títulos de tarjetas modulares, paneles de configuración y secciones principales.
- **Title** (700, 1rem / 16px, line-height 1.4): Encabezados de métricas, nombres de aplicaciones y títulos secundarios.
- **Body** (500, 0.875rem / 14px, line-height 1.5): Textos explicativos, párrafos descriptivos y contenido de celdas en tablas.
- **Label** (700, 0.75rem / 12px, letter-spacing 0.1em, uppercase): Rótulos de campos de formulario, cabeceras de columnas en tablas y badges categóricos.

### Named Rules
**The Sentence Case Rule.** Todos los encabezados, botones, diálogos y mensajes de alerta se escriben en Sentence Case (mayúscula únicamente en la primera letra de la frase o título). Queda estrictamente desaconsejado el Title Case anglosajón.

## Layout

El sistema implementa un modelo de cuadrícula flexible basado en contenedores centrales con un ancho máximo de 1600px (`.container`), márgenes laterales responsivos (2rem en escritorio, 1rem en móviles) y un ritmo vertical fundamentado en múltiplos de 8px (0.5rem, 1rem, 1.5rem, 2rem).

En pantallas de autenticación centradas (SSO, MFA, consentimientos), la interfaz adopta una disposición vertical monocolumna de máximo 28rem (448px) de ancho, flotando sobre un fondo micro-texturado con patrón de cuadrícula de puntos (`.bg-pattern`). En el panel de control administrativo, la navegación superior fija (`.navbar`) provee acceso instantáneo y delimita el área de trabajo con desenfoque de fondo (`backdrop-filter: blur(12px)`).

## Elevation & Depth

Peak Auth utiliza un modelo híbrido dominado por capas tonales y delimitaciones estructurales sutiles. En estado de reposo, la profundidad se transmite mediante el contraste entre la superficie de la tarjeta (`--bg-surface`) y el fondo (`--bg-body`), contenido por un borde perimetral de 1px. Las sombras se reservan para estados interactivos elevados y diálogos modulares flotantes.

### Shadow Vocabulary
- **Subtle Surface** (`box-shadow: 0 1px 2px 0 rgb(0 0 0 / 0.05)`): Elevación basal en tarjetas de reposo (`--shadow-sm`).
- **Interactive Lift** (`box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1)`): Botones primarios y elementos en foco (`--shadow-md`).
- **Modal Dialogue** (`box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.15), 0 10px 10px -5px rgba(0, 0, 0, 0.08)`): Modales nativos y capas flotantes superpuestas.

### Named Rules
**The Border-Before-Shadow Rule.** Ningún contenedor o tarjeta flota únicamente con sombra. La separación estructural siempre comienza con un borde de 1px (`--border-color`) para preservar nitidez en pantallas de baja densidad y modo oscuro.

## Shapes

El lenguaje de formas combina una silueta envolvente moderna con esquinas controladas:
- **Tarjetas y paneles modulares**: Radio curvado pronunciado (`--radius-2xl`: 1rem / 16px).
- **Botones y campos de formulario**: Curvatura ergonómica optimizada para el tacto (`--radius-xl`: 0.75rem / 12px).
- **Insignias e indicadores de estado**: Borde redondeado suave (`--radius-lg`: 0.5rem / 8px o `--radius`: 0.25rem / 4px).
- **Avatares e indicadores lumínicos**: Circunferencia completa (`--radius-full`: 9999px).

## Components

### Buttons
- **Shape:** Radio curvado ergonómico (`border-radius: var(--radius-xl)` / 12px).
- **Primary:** Fondo cobalto (`var(--brand-600)`), texto blanco, padding 0.75rem 1.5rem, tipografía font-weight 700.
- **Hover / Focus:** Transición suave (`transition: all 0.2s`), elevación sutil `translateY(-1px)` y oscurecimiento a `var(--brand-700)`.
- **Secondary:** Fondo neutro (`var(--slate-100)` o `--slate-800`), borde sutil de 1px y texto slate oscuro/claro.
- **Danger:** Fondo suave rosado (`var(--rose-50)` o translúcido en dark), borde rosado y texto `var(--rose-600)`.

### Cards / Containers
- **Corner Style:** Curvatura amplia (`border-radius: var(--radius-2xl)` / 16px).
- **Background:** Superficie limpia (`var(--bg-surface)`).
- **Border:** 1px sólido (`var(--border-color)`).
- **Internal Padding:** 2rem (32px) en escritorio, reduciendo fluidamente a 1.25rem en pantallas reducidas.

### Inputs / Fields
- **Style:** Fondo limpio (`var(--input-bg)`), borde de 1px (`var(--input-border)`), radio de 12px (`var(--radius-xl)`), padding de 0.75rem 1.25rem.
- **Focus:** Anillo de foco perimetral suave de 3px (`box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1)`) con borde coloreado a `var(--brand-500)`.
- **Etiquetas:** Texto en tamaño xs (0.75rem), mayúsculas (`text-transform: uppercase`), tracking espaciado (`0.1em`) y peso 700.

### Badges / Status Chips
- **Style:** Compactos (`padding: 0.25rem 0.625rem`), tipografía 10px en negrita, borde de 1px coordenado con el fondo.
- **Indicator:** Punto circular de 6px (`border-radius: 9999px`) indicando estado vivo (verde, ámbar o rojo).

### Navigation
- **Barra de navegación:** Cabecera fija superior de 4rem de altura con desenfoque de fondo de 12px, delimitada por un borde inferior de 1px.
- **Marca:** Logotipo SVG interactivo con transición de escala en hover (`scale(1.05)`) y tipografía pesada en -0.025em tracking.

## Do's and Don'ts

### Do:
- **Do** utilizar exclusivamente variables semánticas nativas de CSS (`var(--bg-surface)`, `var(--brand-600)`, etc.).
- **Do** redactar todos los textos de la interfaz en español y con formato estricto de Sentence Case.
- **Do** respaldar la elevación interactiva con una micro-transición suave de `-1px` en el eje vertical (`transform: translateY(-1px)`).
- **Do** asegurar que cualquier elemento interactivo cuente con un indicador visual claro de foco accesible (`:focus-visible`).
- **Do** proporcionar contraste cromático completo verificado en ambos modos de visualización (claro y oscuro).

### Don't:
- **Don't** incluir clases de utilidad de Tailwind CSS (`bg-blue-500`, `flex`, `p-4`, etc.). Todo el código debe residir en hojas de estilo Vanilla CSS.
- **Don't** utilizar Title Case anglosajón en títulos o botones (por ejemplo, evitar *"Guardar Cambios En La Aplicación"*; escribir *"Guardar cambios en la aplicación"*).
- **Don't** saturar las vistas con fondos o botones de color cobalto; reservar el color de marca para los puntos focales primarios.
- **Don't** utilizar sombras sin bordes estructurales de 1px de soporte en tarjetas o modales.
- **Don't** mezclar tipografías o recurrir a fuentes externas fuera de la familia Inter establecida.
