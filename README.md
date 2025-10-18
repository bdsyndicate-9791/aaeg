# aaeg
**AAEG v1.2 – Secure, self-contained AJAX endpoint manager for WordPress admin**    A minimal, dependency-free library to safely register, validate, and audit AJAX handlers in WordPress admin. Features per-endpoint nonces, declarative input validation, built-in logging, optional rate limiting, and unit test support — all in a single file.

# AAEG – Admin AJAX Endpoint Gate
v1.2 – Río Magdalena

Estándar para endpoints AJAX seguros en el panel de administración de WordPress.  
Diseñado para ser seguro, autónomo, trazable y sin dependencias externas.

## Características

- Nonce por endpoint (protección contra CSRF)
- Validación declarativa opcional de parámetros (int, string, email, url, bool, array)
- Auditoría completa: logs de acceso y errores con redacción automática de datos sensibles
- Rate limiting opcional por IP
- Modo de prueba integrado para pruebas unitarias
- Compatibilidad amplia: PHP >= 5.6, WordPress >= 4.7
- Un solo archivo: sin dependencias, sin configuración externa

## Instalación

1. Copie `aaeg.php` en su plugin.
2. Inclúyalo al inicio:

```php
require_once plugin_dir_path( __FILE__ ) . 'aaeg.php';
```

No se requiere activación. AAEG se autoinicializa al incluirse.

## Registro de un endpoint

### Ejemplo básico (sin validación)

```php
function mi_handler_basico( $input ) {
    // $input === $_POST (sin sanitizar)
    return array( 'mensaje' => 'Hola desde ' . get_current_user_id() );
}

AAEG::register(
    'saludo_admin',          // Nombre del endpoint
    'mi_handler_basico',     // Función handler
    'manage_options'         // Capability requerida
);
```

### Ejemplo con validación declarativa

```php
function exportar_datos( $datos ) {
    // $datos ya está validado y sanitizado
    $formato = $datos['formato']; // string seguro
    $activo  = $datos['activo'];  // bool
    $email   = $datos['email'];   // email validado

    // Lógica de negocio...
    return array( 'archivo' => 'export.csv' );
}

AAEG::register(
    'exportar_datos',
    'exportar_datos',
    'manage_options',
    array(
        'formato' => 'string',
        'activo'  => 'bool',
        'email'   => 'email',
        'ids'     => 'array'
    )
);
```

Si algún campo falta o es inválido, AAEG rechaza la solicitud automáticamente y registra el error.

## Llamada desde el frontend (JavaScript)

AAEG no incluye ni gestiona JavaScript. Usted controla el frontend.

```js
// El nonce debe generarse en PHP y pasarse al JS
const nonce = window.miPlugin.nonces.exportar_datos;

jQuery.post( ajaxurl, {
    action: 'aaeg_dispatch',
    endpoint: 'exportar_datos',
    aaeg_exportar_datos: nonce,
    formato: 'csv',
    activo: true,
    email: 'admin@ejemplo.com',
    ids: [1, 2, 3]
})
.done( response => {
    if ( response.status === 'ok' ) {
        console.log('Éxito:', response.data);
    } else {
        console.error('Error:', response.message);
    }
});
```

El nombre del campo del nonce siempre es `aaeg_{endpoint}`.

## Modo de prueba (para PHPUnit)

```php
use PHPUnit\Framework\TestCase;

class AAEGTest extends TestCase {
    public function test_endpoint_valido() {
        AAEG::enable_test_mode();
        wp_set_current_user( $this->factory()->user->create( array( 'role' => 'administrator' ) ) );

        $_POST = array(
            'endpoint' => 'saludo_admin',
            'aaeg_saludo_admin' => wp_create_nonce( 'aaeg_saludo_admin' )
        );

        AAEG::dispatch();
        $response = AAEG::get_last_response();

        $this->assertArrayHasKey( 'status', $response );
        $this->assertEquals( 'ok', $response['status'] );
    }
}
```

En modo prueba, no se envían cabeceras, no se llama a `exit()`, y la respuesta se captura para inspección.

## Configuración opcional

Defina estas constantes en `wp-config.php` o en su plugin:

```php
// Logs de acceso y errores
define( 'AAEG_ACCESS_LOG', WP_CONTENT_DIR . '/logs/aaeg-access.log' );
define( 'AAEG_ERROR_LOG',  WP_CONTENT_DIR . '/logs/aaeg-error.log' );

// Proxies de confianza (para IP real en entornos con Cloudflare, etc.)
define( 'AAEG_TRUSTED_PROXIES', array( '192.168.1.10', '10.0.0.5' ) );

// Rate limiting: 15 solicitudes por minuto
define( 'AAEG_RATE_LIMIT', array(
    'window' => 60,
    'max'    => 15
) );
```

Los logs redactan automáticamente campos sensibles como `password`, `token`, `secret`, etc.

## Licencia

- Uso educativo: libre.
- Uso comercial: restringido. Requiere autorización.

© Benjamín Sánchez Cárdenas – 2025

## Notas importantes

- No use `add_action('wp_ajax_...')` directamente. Todo debe registrarse con `AAEG::register()`.
- Los handlers reciben datos no confiables si no se usa esquema. Siempre valide o use el sistema declarativo.
- AAEG es exclusivo para `wp-admin`. No soporta endpoints públicos (`nopriv`).
- Un solo archivo, cero dependencias: ideal para plugins profesionales.

