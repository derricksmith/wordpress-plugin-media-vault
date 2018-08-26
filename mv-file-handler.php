<?php
/**
 * File Request Handling.
 *
 * @package WordPress_Plugin
 * @package MediaVault
 *
 * @author Max G J Panas <http://maxpanas.com/>
 * @license GPL-3.0+
 */

/**
 * Helper function to get attachment by name
 *
 * @since 0.8.13
 *
 * @param string $post_name Filename
 */
if (!(function_exists('mgjp_get_attachment_by_post_name')))
{
    function mgjp_get_attachment_by_post_name($post_name)
    {
        
        // First, try to get by '_wp_attachment_filename' meta
        $args           = array(
            'posts_per_page' => 1,
            'post_type'      => 'attachment',
            'post_status'      => 'any',
            'orderby'      => 'ID',
            'order'      => 'desc',
            'meta_key'       => '_wp_attachment_filename',
            'meta_value'     => $post_name,
        );
        $get_attachment = new WP_Query($args);
       
        if ($get_attachment->posts[0])
        {
            return $get_attachment->posts[0];
        }
        
        // Fails, try post_name too
        $args           = array(
            'posts_per_page' => 1,
            'post_status'      => 'any',
            'orderby'      => 'ID',
            'order'      => 'desc',
            'post_type'      => 'attachment',
            'name'           => trim($post_name),
        );
        $get_attachment = new WP_Query($args);
        
        if ($get_attachment->posts[0])
        {
            return $get_attachment->posts[0];
        }
        
        return false;
        
    }
}

/**
 * Check if file with path $rel_file from WP uploads folder is in a Media Vault protected folder.
 * If it is, verify the user requesting it has permission to access it. After they pass the check,
 * If the 'safeforce' flag has been set for $action, send HTTP Headers forcing file download,
 * otherwise send normal headers and serve the file.
 *
 * @since 0.1
 *
 * @uses mgjp_mv_upload_dir()
 * @uses mgjp_mv_get_the_permissions()
 * @param string $rel_file Filesystem path or filename, must be relative to the WP uploads folder
 * @param string $action Force Download Flag, only acceptable value is 'safeforce'
 */
function mgjp_mv_get_file($rel_file, $action = '')
{
    
    // $rel_file = path to the file to view/download,
    // relative to the WP uploads folder
    // (eg:'/media-vault/2013/10/media-vault-150x150.jpg')
    
    $upload_dir = wp_upload_dir();
    
    // only files in the WP uploads directory are allowed to be accessed:
    $file = rtrim($upload_dir['basedir'], '/') . str_replace('..', '', isset($rel_file) ? $rel_file : '');
    
    //---Basic Checks----------------------------------------------------//
    
    if (!$upload_dir['basedir'] || !is_file($file))
    {
        status_header(404);
        wp_die('404. File not found. ' . $upload_dir['basedir'] . " " . $file);
    }
    
    $mime = wp_check_filetype($file); // Check filetype against allowed filetypes
    
    if (isset($mime['type']) && $mime['type'])
    {
        $mimetype = $mime['type'];
    }
    else
    {
        status_header(403);
        wp_die(__('403. Forbidden.<br/>You cannot directly access files of this type in this directory on this server. Please contact the website administrator.'));
    }
    
    //---Permission Checks-----------------------------------------------//
    
    $file_info = pathinfo($rel_file);
    
    // check if file is protected by checking
    // if it is in the protected folder before
    // doing any permission checks
    if (0 === stripos($file_info['dirname'] . '/', mgjp_mv_upload_dir('/', true)))
    {
        
        // disable caching of this page by caching plugins ------//
        if (!defined('DONOTCACHEPAGE'))
        {
            define('DONOTCACHEPAGE', 1);
        }
        
        if (!defined('DONOTCACHEOBJECT'))
        {
            define('DONOTCACHEOBJECT', 1);
        }
        
        if (!defined('DONOTMINIFY'))
        {
            define('DONOTMINIFY', 1);
        }
        
        //-------------------------------------------------------//
        
        // try and get attachment id from url -------------------//
        
        $attachment = mgjp_get_attachment_by_post_name($file_info['filename']);
        
        if (!$attachment)
        {
            status_header(404);
            wp_die('404. File not found. ' . $upload_dir['basedir'] . " " . $file);
        }
        
        $attachment_id = $attachment->ID;
        
        if (!$permission = mgjp_mv_get_the_permission($attachment_id))
        {
            $permission = get_option('mgjp_mv_default_permission', 'logged-in');
        }
        
        $permissions = mgjp_mv_get_the_permissions();
        
        // permission set up error detection
        $standard_error_txt = ' ' . esc_html__('Therefore for safety and privacy reasons this file is unavailable. Please contact the website administrator.', 'media-vault') . '<p><a href="' . home_url() . '">&larr;' . esc_html__('Return to homepage', 'media-vault') . '</a></p>';
        
        if (!isset($permissions[$permission]))
        {
            wp_die(__('The permissions set for this file are not recognized.', 'media-vault') . $standard_error_txt);
        }
        
        if (!isset($permissions[$permission]['logged_in']))
        {
            $errors[] = 'logged_in';
        }
        if (!isset($permissions[$permission]['cb']))
        {
            $errors[] = 'cb';
        }
        if (isset($errors))
        {
            $error_txt = __('The permissions set for this file have left the following important parameters undefined:', 'media-vault')
                . '<ul><li>\'' . implode('\'</li><li>\'', $errors) . '\'</li></ul>'
                . '<p>' . $standard_error_txt . '</p>';
            wp_die($error_txt);
        }
        
        if ($permissions[$permission]['logged_in'])
        {
            is_user_logged_in() || auth_redirect();
        } // using is_user_logged_in is lighter than using just auth_redirect
        
        if (false !== $permissions[$permission]['cb'])
        {
            
            if (!is_callable($permissions[$permission]['cb']))
            {
                wp_die(__('The permission checking function set in this file\'s permissions is not callable.', 'media-vault') . $standard_error_txt);
            }
            
            $permission_check = call_user_func_array($permissions[$permission]['cb'], array($attachment_id, $rel_file, $file));
            
            if (is_wp_error($permission_check))
            {
                wp_die($permission_check->get_error_message() . $standard_error_txt);
            }
            
            if (true !== $permission_check)
            {
                wp_die(__('You do not have sufficient permissions to view this file.', 'media-vault') . $standard_error_txt);
            }
        }
        
    } // end of permission checks
    
    //-------------------------------------------------------------------//
    
    //header( 'Content-Type: ' . $mimetype ); // always send this
    if (false === strpos($_SERVER['SERVER_SOFTWARE'], 'Microsoft-IIS'))
    {
        header('Content-Length: ' . filesize($file));
    }
    if ('safeforce' !== $action)
    {
        //Force PDF Download
        if ($mimetype !== "application/pdf")
        {
            //--OPEN FILE IN BROWSER functions-------------//
            header('Content-Type: application/octet-stream');
            $last_modified = gmdate('D, d M Y H:i:s', filemtime($file));
            $etag          = '"' . md5($last_modified) . '"';
            header("Last-Modified: $last_modified GMT");
            header('ETag: ' . $etag);
            header('Cache-Control: no-store, no-cache, must-revalidate'); // HTTP 1.1.
            header('Pragma: no-cache'); // HTTP 1.0.
            header('Expires: Thu, 01 Dec 1994 16:00:00 GMT'); // Proxies
            header('Content-Disposition: attachment; filename="' . $file_info['basename'] . '";');
            header('Content-Transfer-Encoding: binary');
            
            // Support for Conditional GET
            $client_etag = isset($_SERVER['HTTP_IF_NONE_MATCH']) ? stripslashes($_SERVER['HTTP_IF_NONE_MATCH']) : false;
            
            if (!isset($_SERVER['HTTP_IF_MODIFIED_SINCE']))
            {
                $_SERVER['HTTP_IF_MODIFIED_SINCE'] = false;
            }
            
            $client_last_modified = trim($_SERVER['HTTP_IF_MODIFIED_SINCE']);
            // If string is empty, return 0. If not, attempt to parse into a timestamp
            $client_modified_timestamp = $client_last_modified ? strtotime($client_last_modified) : 0;
            
            // Make a timestamp for our most recent modification...
            $modified_timestamp = strtotime($last_modified);
            
            if (($client_last_modified && $client_etag)
                ? (($client_modified_timestamp >= $modified_timestamp) && ($client_etag == $etag))
                : (($client_modified_timestamp >= $modified_timestamp) || ($client_etag == $etag))
            )
            {
                status_header(304);
                exit;
            }
        }
        else
        {
            header('Content-Type: application/octet-stream');
            // required for IE, otherwise Content-disposition is ignored
            if (ini_get('zlib.output_compression'))
            {
                ini_set('zlib.output_compression', 'Off');
            }
            
            header('Pragma: public'); // required
            header('Expires: 0');
            header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
            header('Cache-Control: private', false); // required for certain browsers
            header('Content-Disposition: attachment; filename="' . $file_info['basename'] . '";');
            header('Content-Transfer-Encoding: binary');
        }
        
    }
    else
    {
        //--FORCE DOWNLOAD Functions-----------------------//
        
        // required for IE, otherwise Content-disposition is ignored
        if (ini_get('zlib.output_compression'))
        {
            ini_set('zlib.output_compression', 'Off');
        }
        
        header('Pragma: public'); // required
        header('Expires: 0');
        header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
        header('Cache-Control: private', false); // required for certain browsers
        header('Content-Disposition: attachment; filename="' . $file_info['basename'] . '";');
        header('Content-Transfer-Encoding: binary');
        
    }
    
    // If we made it this far, just serve the file
    if (ob_get_length())
    {
        ob_clean();
    }
    
    flush();
    
    readfile($file);
    exit;
}
