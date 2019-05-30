/**
* Matt Gifford, Monkeh Works
* www.monkehworks.com
* ---
* This module connects your application to the Google Indexing API
**/
component {

	// Module Properties
    this.title 				= "Google Indexing API";
    this.author 			= "Matt Gifford";
    this.webURL 			= "https://www.monkehworks.com";
    this.description 		= "This component will provide you with connectivity to the Google Indexing API for any ColdFusion (CFML) application.";
    this.version			= "@version.number@+@build.number@";
    // If true, looks for views in the parent first, if not found, then in the module. Else vice-versa
    this.viewParentLookup 	= true;
    // If true, looks for layouts in the parent first, if not found, then in module. Else vice-versa
    this.layoutParentLookup = true;
    this.entryPoint			= 'googleindex';
    this.modelNamespace		= 'googleindex';
    this.cfmapping			= 'googleindex';
    this.autoMapModels 		= false;

	/**
	 * Configure
	 */
	function configure(){

		// Settings
		settings = {
			filePath      = '',
			tokenEndpoint = '',
			notificationsEndpoint = ''
		};
	}

	/**
	* Fired when the module is registered and activated.
	*/
	function onLoad(){
		parseParentSettings();
		var googleIndexSettings = controller.getConfigSettings().googleindex;

		// Map Library
		binder.map( "googleindex@googleindex" )
			.to( "#moduleMapping#.GoogleIndex" )
			.initArg( name="filePath", 			    value=googleIndexSettings.filePath )
			.initArg( name="tokenEndpoint", 		value=googleIndexSettings.tokenEndpoint )
			.initArg( name="notificationsEndpoint", value=googleIndexSettings.notificationsEndpoint );
	}

	/**
	* Fired when the module is unregistered and unloaded
	*/
	function onUnload(){
	}

	/**
	* parse parent settings
	*/
	private function parseParentSettings(){
		var oConfig 		= controller.getSetting( "ColdBoxConfig" );
		var configStruct 	= controller.getConfigSettings();
		var indexDSL 		= oConfig.getPropertyMixin( "googleindex", "variables", structnew() );

		//defaults
		configStruct.googleindex = variables.settings;

		// incorporate settings
		structAppend( configStruct.googleindex, indexDSL, true );
	}

}