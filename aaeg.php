<?php
/**
 * AAEG v1.2 – Río Magdalena
 * Admin AJAX Endpoint Gate
 *
 * Estándar obligatorio para endpoints AJAX en wp-admin.
 * Compatible con PHP >= 5.6 y WordPress >= 4.7.
 *
 * Responsabilidades:
 * 1. Registro de endpoints
 * 2. Despacho y control de flujo
 * 3. Validación y sanitización declarativa (opcional)
 * 4. Seguridad: nonce, capability, IP, cabeceras
 * 5. Salida JSON y compatibilidad
 * 6. Auditoría y logging seguro
 * 7. Rate limiting por proceso (opcional)
 * 8. Soporte para pruebas unitarias
 *
 * @license Interno: uso educativo libre, uso comercial restringido.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'AAEG' ) ) :

class AAEG {

    // ─────────────────────────────────────
    // 1. ESTADO INTERNO Y CONFIGURACIÓN
    // ─────────────────────────────────────

    private static $registry = array();
    private static $rate_limits = array();
    private static $test_mode = false;
    private static $last_response = null;


    // ─────────────────────────────────────
    // 2. REGISTRO DE ENDPOINTS
    // ─────────────────────────────────────

    public static function register( $name, $handler, $capability = 'manage_options', $schema = null ) {
        if ( isset( self::$registry[ $name ] ) ) {
            if ( function_exists( '_doing_it_wrong' ) ) {
                _doing_it_wrong(
                    __CLASS__ . '::register',
                    sprintf( 'El endpoint "%s" ya está registrado.', esc_html( $name ) ),
                    'AAEG v1.2'
                );
            }
            return;
        }

        if ( ! preg_match( '/^[a-zA-Z0-9_-]+$/', $name ) ) {
            if ( function_exists( '_doing_it_wrong' ) ) {
                _doing_it_wrong(
                    __CLASS__ . '::register',
                    'Nombre de endpoint inválido. Solo se permiten letras, números, guiones y guiones bajos.',
                    'AAEG v1.2'
                );
            }
            return;
        }

        self::$registry[ $name ] = array(
            'handler'    => $handler,
            'capability' => $capability,
            'schema'     => $schema,
        );
    }


    // ─────────────────────────────────────
    // 3. SOPORTE PARA PRUEBAS UNITARIAS
    // ─────────────────────────────────────

    public static function enable_test_mode() {
        self::$test_mode = true;
    }

    public static function get_last_response() {
        return self::$last_response;
    }


    // ─────────────────────────────────────
    // 4. DESPACHO Y CONTROL DE FLUJO
    // ─────────────────────────────────────

    public static function dispatch() {
        $result = self::process_request();
        if ( self::$test_mode ) {
            self::$last_response = $result;
            return $result;
        }

        if ( is_wp_error( $result ) ) {
            self::send_json_error( $result->get_error_message(), $result->get_error_code() ?: 400 );
        } else {
            self::send_json( $result );
        }

        exit;
    }

    protected static function process_request() {
        // Rate limiting
        if ( self::should_rate_limit() ) {
            $ip = self::get_client_ip();
            if ( self::is_rate_limited( $ip ) ) {
                self::log_access( 'rate_limited', array( 'ip' => $ip ) );
                return new WP_Error( 'rate_limited', 'Demasiadas solicitudes.', array( 'status' => 429 ) );
            }
        }

        $endpoint = isset( $_POST['endpoint'] ) ? sanitize_key( $_POST['endpoint'] ) : '';
        if ( empty( $endpoint ) ) {
            self::log_access( 'missing_endpoint', array( 'ip' => self::get_client_ip() ) );
            return new WP_Error( 'missing_endpoint', 'Endpoint requerido.', array( 'status' => 400 ) );
        }

        // Validación de nonce por endpoint
        $nonce_key = 'aaeg_' . $endpoint;
        if ( ! isset( $_POST[ $nonce_key ] ) || ! wp_verify_nonce( $_POST[ $nonce_key ], $nonce_key ) ) {
            self::log_access( 'nonce_fail', array( 'endpoint' => $endpoint, 'ip' => self::get_client_ip() ) );
            return new WP_Error( 'nonce_fail', 'Nonce inválido.', array( 'status' => 403 ) );
        }

        if ( ! isset( self::$registry[ $endpoint ] ) ) {
            self::log_access( 'endpoint_not_found', array( 'endpoint' => $endpoint, 'ip' => self::get_client_ip() ) );
            return new WP_Error( 'endpoint_not_found', 'Endpoint no registrado.', array( 'status' => 400 ) );
        }

        $config = self::$registry[ $endpoint ];
        $cap = $config['capability'];

        if ( ! current_user_can( $cap ) ) {
            self::log_access( 'capability_denied', array(
                'endpoint' => $endpoint,
                'cap'      => $cap,
                'user'     => get_current_user_id(),
                'ip'       => self::get_client_ip()
            ) );
            return new WP_Error( 'capability_denied', 'Acceso denegado.', array( 'status' => 403 ) );
        }

        // Validación y sanitización opcional
        $input = $_POST;
        if ( ! empty( $config['schema'] ) && is_array( $config['schema'] ) ) {
            $validated = self::validate_and_sanitize( $input, $config['schema'] );
            if ( is_wp_error( $validated ) ) {
                self::log_access( 'validation_failed', array(
                    'endpoint' => $endpoint,
                    'errors'   => $validated->get_error_messages(),
                    'ip'       => self::get_client_ip()
                ) );
                return $validated;
            }
            $input = $validated;
        }

        $handler = $config['handler'];
        try {
            $result = call_user_func( $handler, $input );

            if ( ! is_array( $result ) ) {
                $result = array( 'status' => 'ok', 'data' => $result );
            }
            if ( ! isset( $result['status'] ) ) {
                $result['status'] = 'ok';
            }

            self::log_access( 'success', array(
                'endpoint' => $endpoint,
                'user'     => get_current_user_id(),
                'ip'       => self::get_client_ip()
            ) );
            return $result;
        } catch ( Exception $e ) {
            self::log_error( 'handler_exception', array(
                'endpoint' => $endpoint,
                'message'  => $e->getMessage(),
                'trace'    => defined( 'WP_DEBUG' ) && WP_DEBUG ? $e->getTraceAsString() : 'disabled',
                'ip'       => self::get_client_ip()
            ) );
            return new WP_Error( 'handler_exception', 'Error interno del endpoint.', array( 'status' => 500 ) );
        }
    }


    // ─────────────────────────────────────
    // 5. VALIDACIÓN Y SANITIZACIÓN DECLARATIVA
    // ─────────────────────────────────────

    protected static function validate_and_sanitize( $input, $schema ) {
        $output = array();

        foreach ( $schema as $key => $type ) {
            if ( ! isset( $input[ $key ] ) ) {
                return new WP_Error( 'missing_field', "Campo requerido faltante: {$key}" );
            }

            $value = $input[ $key ];

            switch ( $type ) {
                case 'int':
                    if ( ! is_numeric( $value ) ) {
                        return new WP_Error( 'invalid_type', "El campo {$key} debe ser numérico." );
                    }
                    $output[ $key ] = (int) $value;
                    break;

                case 'bool':
                    $output[ $key ] = filter_var( $value, FILTER_VALIDATE_BOOLEAN );
                    break;

                case 'email':
                    $sanitized = sanitize_email( $value );
                    if ( ! is_email( $sanitized ) ) {
                        return new WP_Error( 'invalid_email', "El campo {$key} no es un email válido." );
                    }
                    $output[ $key ] = $sanitized;
                    break;

                case 'url':
                    $sanitized = esc_url_raw( $value );
                    if ( empty( $sanitized ) ) {
                        return new WP_Error( 'invalid_url', "El campo {$key} no es una URL válida." );
                    }
                    $output[ $key ] = $sanitized;
                    break;

                case 'array':
                    if ( ! is_array( $value ) ) {
                        if ( is_string( $value ) ) {
                            $decoded = json_decode( $value, true );
                            if ( json_last_error() !== JSON_ERROR_NONE || ! is_array( $decoded ) ) {
                                return new WP_Error( 'invalid_array', "El campo {$key} debe ser un array válido." );
                            }
                            $value = $decoded;
                        } else {
                            return new WP_Error( 'invalid_array', "El campo {$key} debe ser un array." );
                        }
                    }
                    $output[ $key ] = array_map( 'sanitize_text_field', $value );
                    break;

                case 'string':
                default:
                    $output[ $key ] = sanitize_text_field( $value );
                    break;
            }
        }

        return $output;
    }


    // ─────────────────────────────────────
    // 6. SEGURIDAD Y DEFENSA
    // ─────────────────────────────────────

    private static function get_client_ip() {
        $ip = '0.0.0.0';
        $trusted_proxies = defined( 'AAEG_TRUSTED_PROXIES' ) ? (array) AAEG_TRUSTED_PROXIES : array();
        $use_forwarded = ! empty( $trusted_proxies );

        if ( $use_forwarded && ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
            $remote_addr = $_SERVER['REMOTE_ADDR'];
            if ( ! in_array( $remote_addr, $trusted_proxies, true ) ) {
                $use_forwarded = false;
            }
        } else {
            $use_forwarded = false;
        }

        if ( $use_forwarded ) {
            $keys = array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP' );
            foreach ( $keys as $key ) {
                if ( ! empty( $_SERVER[ $key ] ) ) {
                    $ip_list = explode( ',', $_SERVER[ $key ] );
                    $ip = trim( $ip_list[0] );
                    if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
                        return $ip;
                    }
                }
            }
        }

        if ( ! empty( $_SERVER['REMOTE_ADDR'] ) && filter_var( $_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP ) ) {
            $ip = $_SERVER['REMOTE_ADDR'];
        }

        return $ip;
    }

    private static function send_security_headers() {
        header( 'X-Content-Type-Options: nosniff' );
    }


    // ─────────────────────────────────────
    // 7. SALIDA JSON Y COMPATIBILIDAD
    // ─────────────────────────────────────

    private static function send_json( $data ) {
        if ( ! self::$test_mode ) {
            self::send_security_headers();
        }
        if ( function_exists( 'wp_send_json' ) && ! self::$test_mode ) {
            wp_send_json( $data );
        } else {
            if ( ! self::$test_mode ) {
                header( 'Content-Type: application/json; charset=' . get_option( 'blog_charset' ) );
            }
            $json = json_encode( $data );
            if ( self::$test_mode ) {
                return $json;
            }
            echo $json;
            if ( function_exists( 'wp_die' ) && ! self::$test_mode ) {
                wp_die();
            } elseif ( ! self::$test_mode ) {
                die();
            }
        }
    }

    private static function send_json_error( $message, $status_code = 400 ) {
        if ( ! self::$test_mode ) {
            self::send_security_headers();
        }
        $response = array(
            'status'  => 'error',
            'message' => $message,
        );

        if ( function_exists( 'wp_send_json_error' ) && ! self::$test_mode ) {
            if ( version_compare( $GLOBALS['wp_version'], '4.7', '>=' ) ) {
                wp_send_json_error( $response, $status_code );
            } else {
                http_response_code( $status_code );
                wp_send_json_error( $response );
            }
        } else {
            if ( ! self::$test_mode ) {
                http_response_code( $status_code );
                header( 'Content-Type: application/json; charset=' . get_option( 'blog_charset' ) );
            }
            $json = json_encode( $response );
            if ( self::$test_mode ) {
                return $json;
            }
            echo $json;
            if ( function_exists( 'wp_die' ) && ! self::$test_mode ) {
                wp_die();
            } elseif ( ! self::$test_mode ) {
                die();
            }
        }
    }


    // ─────────────────────────────────────
    // 8. AUDITORÍA Y LOGGING SEGURO
    // ─────────────────────────────────────

    private static function log_access( $event, $context = array() ) {
        if ( defined( 'AAEG_ACCESS_LOG' ) && AAEG_ACCESS_LOG && function_exists( 'error_log' ) ) {
            $safe_context = self::sanitize_log_context( $context );
            $log = sprintf(
                "[%s] AAEG ACCESS: %s | %s\n",
                gmdate( 'Y-m-d H:i:s' ),
                $event,
                json_encode( $safe_context, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE )
            );
            error_log( $log, 3, AAEG_ACCESS_LOG );
        }
    }

    private static function log_error( $error, $context = array() ) {
        if ( defined( 'AAEG_ERROR_LOG' ) && AAEG_ERROR_LOG && function_exists( 'error_log' ) ) {
            $safe_context = self::sanitize_log_context( $context );
            $log = sprintf(
                "[%s] AAEG ERROR: %s | %s\n",
                gmdate( 'Y-m-d H:i:s' ),
                $error,
                json_encode( $safe_context, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE )
            );
            error_log( $log, 3, AAEG_ERROR_LOG );
        }
    }

    private static function sanitize_log_context( $data ) {
        $sensitive_keys = array( 'password', 'pass', 'token', 'secret', 'auth', 'nonce' );
        array_walk_recursive( $data, function ( &$value, $key ) use ( $sensitive_keys ) {
            if ( in_array( strtolower( $key ), $sensitive_keys, true ) ) {
                $value = '[REDACTED]';
            }
        } );
        return $data;
    }


    // ─────────────────────────────────────
    // 9. RATE LIMITING (OPCIONAL)
    // ─────────────────────────────────────

    private static function should_rate_limit() {
        return defined( 'AAEG_RATE_LIMIT' ) && AAEG_RATE_LIMIT;
    }

    private static function is_rate_limited( $ip ) {
        if ( ! self::should_rate_limit() ) {
            return false;
        }

        $window = 60;
        $max_requests = 10;

        if ( is_array( AAEG_RATE_LIMIT ) ) {
            $window = isset( AAEG_RATE_LIMIT['window'] ) ? (int) AAEG_RATE_LIMIT['window'] : $window;
            $max_requests = isset( AAEG_RATE_LIMIT['max'] ) ? (int) AAEG_RATE_LIMIT['max'] : $max_requests;
        }

        $now = time();
        $cleanup_threshold = $now - $window;

        foreach ( self::$rate_limits as $stored_ip => $data ) {
            if ( $data[0] < $cleanup_threshold ) {
                unset( self::$rate_limits[ $stored_ip ] );
            }
        }

        if ( ! isset( self::$rate_limits[ $ip ] ) ) {
            self::$rate_limits[ $ip ] = array( $now, 1 );
            return false;
        }

        list( $timestamp, $count ) = self::$rate_limits[ $ip ];

        if ( $timestamp < $cleanup_threshold ) {
            self::$rate_limits[ $ip ] = array( $now, 1 );
            return false;
        }

        if ( $count >= $max_requests ) {
            return true;
        }

        self::$rate_limits[ $ip ][1]++;
        return false;
    }


    // ─────────────────────────────────────
    // 10. INICIALIZACIÓN
    // ─────────────────────────────────────

    public static function init() {
        add_action( 'wp_ajax_aaeg_dispatch', array( __CLASS__, 'dispatch' ) );
    }
}

AAEG::init();

endif;