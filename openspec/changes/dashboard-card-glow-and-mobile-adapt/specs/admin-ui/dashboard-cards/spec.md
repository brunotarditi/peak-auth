# Spec Delta

## Purpose

Define el comportamiento visual, la animación perimetral continua ("Halo Sentinel"), la accesibilidad y los estados de interacción de las tarjetas de aplicaciones registradas en el dashboard administrativo de Peak Auth.

## ADDED Requirements

### Requirement: Perimeter border lighting animation
The application cards in the dashboard SHALL render an infinite subtle border glow animation to convey active status and visual depth without using high-contrast neon effects.

#### Scenario: Normal display with animation
- **WHEN** the dashboard renders application cards
- **THEN** each card displays a subtle rotating perimeter lighting along its border using native CSS.

### Requirement: Respect reduced motion preference
The application cards SHALL respect the user's operating system reduced motion preferences.

#### Scenario: User enables prefers-reduced-motion
- **WHEN** the user has `prefers-reduced-motion: reduce` configured in their browser or OS
- **THEN** the perimeter lighting animation is disabled and replaced by a static refined accent border.

### Requirement: Interactive hover and active states
The application cards SHALL provide subtle visual feedback on hover and active states.

#### Scenario: Pointer hovers over application card
- **WHEN** a user hovers over an application card with a pointing device
- **THEN** the card gently elevates and slightly deepens its shadow with the brand accent color.

### Requirement: Sentence case copy on card actions
The action buttons and contextual links within the application card SHALL be presented in Spanish Sentence Case.

#### Scenario: Viewing card action buttons
- **WHEN** application card actions are displayed
- **THEN** button labels and links are formatted as "Configuración" and "Usuarios" instead of uppercase text.
