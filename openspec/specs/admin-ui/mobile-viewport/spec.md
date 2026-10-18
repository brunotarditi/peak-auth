# admin-ui/mobile-viewport Specification

## Purpose
Define las especificaciones responsivas, dimensiones táctiles mínimas y adaptaciones ergonómicas para dispositivos móviles y pantallas estrechas en la consola administrativa de Peak Auth.

## Requirements

### Requirement: Minimum touch target dimensions
All primary interactive elements in the admin console on mobile viewports SHALL meet accessible touch target dimensions of at least 44 by 44 CSS pixels.

#### Scenario: Mobile user taps action buttons or links
- **WHEN** a user interacts with buttons, icons, or navigation items on a mobile viewport
- **THEN** the clickable/tappable bounding area is at least 44px by 44px to prevent accidental mis-taps.

### Requirement: Responsive mobile layout and padding
The layout container and cards SHALL dynamically adjust spacing and padding on mobile screens without horizontal clipping or scrollbar overflows.

#### Scenario: Viewing dashboard on screen narrower than 640px
- **WHEN** the viewport width is less than 640px
- **THEN** card padding and grid columns adjust to a single fluid column with ergonomic edge spacing.
