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

		// constants for search base
		define( "GROUPDN", 0 );
		define( "USERDN", 1 );
		define( "DEFAULTDN", 2 );

		// constants for error reporting
		define( "NONSENSITIVE", 1 );
		define( "SENSITIVE", 2 );
		define( "HIGHLYSENSITIVE", 3 );

		$ldap = LdapAuthenticationPlugin::getInstance();

		if ( $wgLDAPUseAutoAuth ) {
			if ( $ldap->getConf( "AutoAuthDomain" ) !== "" ) {
				$ldap->autoAuthSetup();
			}
		}
	}

	public static function onPersonalUrls( array &$personal_urls, Title $title, SkinTemplate $skin ) {
		global $wgLDAPUseAutoAuth;
		$auth = LdapAuthenticationPlugin::getInstance();
		$auth->printDebug( "Entering NoLogout.", NONSENSITIVE );
		if ( $wgLDAPUseAutoAuth && $auth->getConf( "AutoAuthUsername" ) !== "" &&
			$auth->getConf( "AutoAuthDomain" ) !== "" ) {
			$auth->autoAuthSetup();
			unset( $personal_urls['logout'] );
		}
	}
}
