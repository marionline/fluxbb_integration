<?php
/**
 *---------------------------------------------------------------------------
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *---------------------------------------------------------------------------
 *
 * @file
 * Common function in fluxbb_posts and fluxbb_login modules
 */

/**
 * get_forum_url 
 * Return the fluxbb forum url
 * 
 * @access public
 * @return string
 */
function get_forum_url() {
  $url = trim(variable_get('fluxbb_integration_url_path', 'http://www.example.com/forum'));
  if(substr($url, -1) == '/')
    return substr($url, 0, -1);
  else
    return $url;
}

/**
 * get_fluxbb_object 
 * 
 * @access public
 * @return fluxbb object from fluxbb-api.php
 */
function get_fluxbb_object() {
  $pun_root = variable_get('fluxbb_integration_root_path', 'forum/');
  if(!is_dir($pun_root)){
    return false;
  } else {
    include_once('fluxbb-api.php');
    return new fluxbb($pun_root);
  }
}

