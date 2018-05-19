<?php
/**
 * Secondary authentication provider wrapper for LdapAuthentication
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 * http://www.gnu.org/copyleft/gpl.html
 *
 * @file
 * @ingroup Auth
 */

use MediaWiki\Session\CookieSessionProvider;
use MediaWiki\Session\SessionInfo;
use MediaWiki\Session\UserInfo;

class LdapSessionAuthenticationProvider extends CookieSessionProvider {

	public function __construct() {
		$params = [
				'priority' => 50
		];
		parent::__construct( $params );
	}

	/**
	 * Does the web server authentication piece of the LDAP plugin.
	 *
	 *$param $request WebRequest
	 * @return SessionInfo|null
	 */
	public function provideSessionInfo( WebRequest $request ) {
		global $wgLDAPUseAutoAuth;

		$session = parent::provideSessionInfo( $request );
		if ( !$wgLDAPUseAutoAuth ) {
			return $session;
		}

		$ldap = LdapAuthenticationPlugin::getInstance();

		$ldap->printDebug( "Entering AutoAuthentication.", NONSENSITIVE );

		$session = parent::provideSessionInfo( $request );
		if ( defined( 'MW_NO_SESSION' ) ) {
			wfDebugLog(
				__METHOD__,
				"No session for request: " . $_SERVER['REQUEST_URI']
			);
			return $session;
		}
		
		if ( $session === null ) {
			//echo implode( "\n", $request->getAllHeaders() );
			//print_r( $request->getAllHeaders() );
			// 'REMOTE_User' doesn't exist in the header - it needs to be pulled from $_SERVER[] or getenv()
			// See the Auth_remoteuser extension for more details
			$username = $request->getHeader( 'REMOTE_USER' );

			$ldap->printDebug( "Calling auto-auth setup.", NONSENSITIVE );

			// Let regular authentication plugins configure themselves for auto
			// authentication chaining
			$ldap->autoAuthSetup();

			$autoauthname = preg_replace( '/@.*/', '', $username );
			$ldap->printDebug( "Changing username from '$username' to '$autoauthname'.", NONSENSITIVE );

			$autoauthname = $ldap->getConf( 'AutoAuthUsername' );
			$ldap->printDebug( "Calling authenticate with username ($autoauthname).", NONSENSITIVE );

			if ( strlen( $autoauthname ) === 0 ) {
				$ldap->printDebug( "Username was empty, returning no session", NONSENSITIVE );
				return null;
			}

			// The user hasn't already been authenticated, let's check them
			$authenticated = $ldap->authenticate( $autoauthname, '' );
			if ( !$authenticated ) {
				// If the user doesn't exist in LDAP, there isn't much reason to
				// go any further.
				$ldap->printDebug( "User wasn't found in LDAP, exiting.", NONSENSITIVE );
				return false;
			}

			// We need the username that MediaWiki will always use, not necessarily the one we
			// get from LDAP.
			$mungedUsername = $ldap->getCanonicalName( $autoauthname );

			$ldap->printDebug(
				"User exists in LDAP; finding the user by name ($mungedUsername) in MediaWiki.",
				NONSENSITIVE
			);
			$localId = User::idFromName( $mungedUsername );
			$ldap->printDebug( "Got id ($localId).", NONSENSITIVE );

			$user = User::newFromSession( $request ); // TODO: or use User::newFromName( $mungedUsername );?
			// Is the user already in the database?
			if ( !$localId ) {
				$userAdded = self::attemptAddUser( $user, $mungedUsername );
				if ( !$userAdded ) {
					return $session;
				}
			} else {
				$ldap->printDebug( "User exists in local database, logging in.", NONSENSITIVE );
				
				$user->setID( $localId );
				$user->loadFromId();
				$ldap->updateUser( $user );
			}

			//$user->setCookies();
			//wfSetupSession();

			$info = [
					'userInfo' => UserInfo::newFromName( $mungedUsername, true ),
					'provider' => $this
			];
			$session = new SessionInfo( $this->priority, $info );
		}

		return $session;
	}

	/**
	 * @param $user User
	 * @param $mungedUsername String
	 * @return bool
	 */
	public static function attemptAddUser( $user, $mungedUsername ) {
		$ldap = LdapAuthenticationPlugin::getInstance();

		if ( !$ldap->autoCreate() ) {
			$ldap->printDebug( "Cannot automatically create accounts.", NONSENSITIVE );
			return false;
		}

		$ldap->printDebug( "User does not exist in local database; creating.", NONSENSITIVE );
		// Checks passed, create the user
		$user->loadDefaults( $mungedUsername );
		$status = $user->addToDatabase();
		if ( $status !== null && !$status->isOK() ) {
			$ldap->printDebug( "Creation failed: " . $status->getWikiText(), NONSENSITIVE );
			return false;
		}
		$ldap->initUser( $user, true );
		# Update user count
		$ssUpdate = new SiteStatsUpdate( 0, 0, 0, 0, 1 );
		$ssUpdate->doUpdate();
		# Notify hooks (e.g. Newuserlog)
		//Hooks::run( 'AuthPluginAutoCreate', [ $user ] );

		return true;
	}
}