<?php
/**
 * Hooks for LdapAuthentication extension
 *
 * @file
 * @ingroup Extensions
 */

class LdapAuthenticationHooks {

	/**
	 * @param $updater DatabaseUpdater
	 * @return bool
	 */
	public static function onLdapAuthenticationSchemaUpdates( $updater ) {
		$base = __DIR__;
		switch ( $updater->getDB()->getType() ) {
		case 'mysql':
		case 'sqlite':
			$updater->addExtensionTable( 'ldap_domains', "$base/schema/ldap-mysql.sql" );
			break;
		case 'postgres':
			$updater->addExtensionTable( 'ldap_domains', "$base/schema/ldap-postgres.sql" );
			break;
		}
		return true;
	}

	public static function onRegistration() {
		global $wgLDAPUseAutoAuth;
		global $wgAuth;

		// constants for search base
		define( "GROUPDN", 0 );
		define( "USERDN", 1 );
		define( "DEFAULTDN", 2 );

		// constants for error reporting
		define( "NONSENSITIVE", 1 );
		define( "SENSITIVE", 2 );
		define( "HIGHLYSENSITIVE", 3 );

		$wgAuth = LdapAuthenticationPlugin::getInstance();

		if ( $wgLDAPUseAutoAuth ) {
			self::AutoAuthSetup();
		}
	}

	// The auto-auth code was originally derived from the SSL Authentication plugin
	// http://www.mediawiki.org/wiki/SSL_authentication
	
	/**
	 * Sets up the auto-authentication piece of the LDAP plugin.
	 *
	 * @access public
	 */
	private static function AutoAuthSetup() {
		global $wgHooks;
		global $wgAuth;
		global $wgDisableAuthManager;
		global $wgLDAPUseAutoAuth;

		if ( class_exists( MediaWiki\Auth\AuthManager::class ) && empty( $wgDisableAuthManager ) ) {
			if ( $wgLDAPUseAutoAuth ) {
				$ldap = LdapAuthenticationPlugin::getInstance();
				if ( $ldap->getConf( "AutoAuthDomain" ) !== "" ) {
					$ldap->autoAuthSetup();
				}
				return;
			}
			
			/**
			 * @todo If you want to make AutoAuthSetup() work in an AuthManager
			 *  world, what you need to do is figure out how to do it with a
			 *  SessionProvider instead of the hackiness below. You'll probably
			 *  want an ImmutableSessionProviderWithCookie subclass where
			 *  provideSessionInfo() does the first part of
			 *  LdapAutoAuthentication::Authenticate() (stop before the $localId
			 *  bit).
			 */
			throw new BadFunctionCallException( 'AutoAuthSetup() is not supported with AuthManager.' );
		}

		$wgAuth = LdapAuthenticationPlugin::getInstance();

		$wgAuth->printDebug( "Entering AutoAuthSetup.", NONSENSITIVE );

		# We need both authentication username and domain (bug 34787)
		if ( $wgAuth->getConf( "AutoAuthUsername" ) !== "" &&
			$wgAuth->getConf( "AutoAuthDomain" ) !== ""
		) {
			$wgAuth->printDebug(
				"wgLDAPAutoAuthUsername and wgLDAPAutoAuthDomain is not null, adding hooks.",
				NONSENSITIVE
			);
			//$wgHooks['UserLoadAfterLoadFromSession'][] = 'LdapAutoAuthentication::Authenticate';

			// Disallow logout link
			//$wgHooks['PersonalUrls'][] = 'LdapAutoAuthentication::NoLogout';

			$wgAuth->autoAuthSetup();
		}
	}

	public static function onUserLoadAfterLoadFromSession( $user ) {
		global $wgLDAPUseAutoAuth;
		global $wgAuth;
		if ( $wgLDAPUseAutoAuth && $wgAuth->getConf( "AutoAuthUsername" ) !== "" &&
			$wgAuth->getConf( "AutoAuthDomain" ) !== "" ) {
			$wgAuth->autoAuthSetup();
			LdapAutoAuthentication::Authenticate( $user );
		}
	}

	public static function onPersonalUrls( array &$personal_urls, Title $title, SkinTemplate $skin ) {
		global $wgLDAPUseAutoAuth;
		global $wgAuth;
		if ( $wgLDAPUseAutoAuth && $wgAuth->getConf( "AutoAuthUsername" ) !== "" &&
			$wgAuth->getConf( "AutoAuthDomain" ) !== "" ) {
			$wgAuth->autoAuthSetup();
			LdapAutoAuthentication::NoLogout( $personal_urls, $title, $skin );
		}
	}
}
