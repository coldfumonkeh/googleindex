/**
* Name: GoogleIndex.cfc
* Author: Matt Gifford (matt@monkehworks.com)
* Purpose: To interact with the Google Indexing API using service credentials
*/
component accessors="true" {

    property name="credentialsJSON";
    property name="tokenEndpoint" type="string" default="";
    property name="notificationsEndpoint" type="string" default="";
    property name="accessToken" type="string" default="";

    /**
    * Constructor Method
    * 
    * @filePath The file path to the credentials JSON file
    * @tokenEndpoint The endpoint to call when making the access token request.
    */
    public function init(
        required string filePath,
        required string tokenEndpoint = 'https://www.googleapis.com/oauth2/v4/token',
        required string notificationsEndpoint = 'https://indexing.googleapis.com/v3/urlNotifications'
    ){
        loadCredentialsFile( arguments.filePath );
        setTokenEndpoint( arguments.tokenEndpoint );
        setNotificationsEndpoint( arguments.notificationsEndpoint );
        return this;
    }

    /**
    * Add / Update a URL
    * 
    * @url The fully-qualified location of the item that you want to update
    */
    public struct function updateURL( required string url ){
        return makeIndexRequest(
            url     = arguments.url,
            type    = 'URL_UPDATED'
        );
    }

    /**
    * Remove a URL
    * 
    * @url The fully-qualified location of the item that you want to remove
    */
    public struct function removeURL( required string url ){
        return makeIndexRequest(
            url     = arguments.url,
            type    = 'URL_DELETED'
        );
    }

    /**
    * Returns metadata information about the notification for the given url
    * 
    * @@url The fully-qualified location of the item that you want to fetch metadata for
    */
    public struct function getStatus( required string url ){
        var encodedURL = urlEncodedFormat( arguments.url );
        var result = '';
        cfhttp( url='#getNotificationsEndpoint()#/metadata?url=#encodedURL#', method='GET', result='result' ){
            cfhttpparam( type='header', name='Authorization', value='#buildAuthHeader()#' );
        }
        return deserializeJSON( result[ 'fileContent' ] );
    }

    /**
    * Makes a call to the auth server to return the access token
    */
    public struct function getAccessToken(){
        var JWTPayload = buildJWT();
        var result = '';
        cfhttp( url=getTokenEndpoint(), method='POST', result='result' ){
            cfhttpparam( type='formfield', name='grant_type', value='urn:ietf:params:oauth:grant-type:jwt-bearer' );
            cfhttpparam( type='formfield', name='assertion', value=JWTPayload );
        }
        var stuResponse = deserializeJSON( result[ 'fileContent' ] );
        setAccessToken( stuResponse.access_token ?: '' );
        return stuResponse;
    }

    /**********************
    *** PRIVATE METHODS ***
    ***********************/

    /**
    * Returns the auth header value for protected API calls
    */
    private string function buildAuthHeader(){
        var strAuthHeader = '#getAccessToken()[ 'token_type' ]# #getAccessToken()[ 'access_token' ]#';
        return strAuthHeader;
    }

    /**
    * Makes a request to the API to perform an action
    * 
    * @url The fully-qualified location of the item that you want to update or remove
    * @type The type of notification that you submitted
    */
    private struct function makeIndexRequest(
        required string url,
        required string type
    ){
        var stuBodyContent = {
            'url' : arguments.url,
            'type': arguments.type
        };
        var result = '';
        if 	( getEngine() == "LUCEE" ) {
            cfhttp( url='#getNotificationsEndpoint()#:publish', method='POST', result='result', encodeurl=false ){
                cfhttpparam( type='header', name='Authorization', value='#buildAuthHeader()#' );
                cfhttpparam( type='header', name='Content-Type', value='application/json' );
                cfhttpparam( type='body', value='#serializeJSON( stuBodyContent )#' );
            }
        } else {
            cfhttp( url='#getNotificationsEndpoint()#:publish', method='POST', result='result' ){
                cfhttpparam( type='header', name='Authorization', value='#buildAuthHeader()#' );
                cfhttpparam( type='header', name='Content-Type', value='application/json' );
                cfhttpparam( type='body', value='#serializeJSON( stuBodyContent )#' );
            }
        }

        return deserializeJSON( result[ 'fileContent' ] );
    }

    /**
    * Builds the JWT needed for access token requests
    */
    private string function buildJWT(){
        var currDateTime  = now();
        var dtGMT         = dateAdd( 's', getTimeZoneInfo().UTCTotalOffset, currDateTime );
        var assertionTime = dateAdd( 's', 600, dtGMT );
        var expiryTime    = dateAdd( 'n', 60, assertionTime );
        var credJSON      = getCredentialsJSON();
        
        var payload       = {
            'iss'  : credJSON[ 'client_email' ],
            'scope': 'https://www.googleapis.com/auth/indexing',
            'aud'  : getTokenEndpoint(),
            'exp'  : generateEpochTime( expiryTime ),
            'iat'  : generateEpochTime( assertionTime )
        };
        return encode( payload = payload );
    }

    /**
    * Loads the credentials file and stores the CFML representation into the component
    * 
    * @filePath The file path to the .json file
    */
    private function loadCredentialsFile( required string filePath ){
        if( fileExists( arguments.filePath ) ){
            var fileData = fileRead( arguments.filePath );
            setCredentialsJSON( deserializeJSON( fileData ) );
        } else {
            throw( message = 'The given file (#arguments.filePath#) does not exist' );
        }
    }

    /**
    * Returns a signed version of the provided partial JWT string
    * 
    * @input The incomplete JWT to be signed
    */
    private function signSHA256RSA( required string input ){
        var b64              = createObject( "java", "java.util.Base64" );
        var pkSpec           = createObject( "java", "java.security.spec.PKCS8EncodedKeySpec" );
        var keyFactory       = createObject( "java", "java.security.KeyFactory" );
        var signature        = createObject( "java", "java.security.Signature" );
        var b1               = b64.getDecoder().decode( getRealPK() );
        var spec             = pkSpec.init( b1 );
        var kf               = keyFactory.getInstance( "RSA" );
        var privateSignature = signature.getInstance( "SHA256withRSA" );
        privateSignature.initSign( kf.generatePrivate( spec ) );
        privateSignature.update( arguments.input.getBytes( "UTF-8" ) );
        return base64UrlEscape( toBase64( privateSignature.sign() ) );
    }

    /**
	* Escapes unsafe url characters from a base64 string
	* @value The string to manipulate
	*/
	private function base64UrlEscape( required string value ){
		return reReplace( reReplace( reReplace( arguments.value, "\+", "-", "all" ), "\/", "_", "all" ) ,"=", "", "all" );
	}

	/**
	* Restore base64 characters from an url escaped string 
	* @value The string to manipulate
	*/
	private function base64UrlUnescape( required string value ){
		var base64String = reReplace( reReplace( arguments.value, "\-", "+", "all" ), "\_", "/", "all" );
		var padding = repeatstring( "=", 4 - len( base64String ) mod 4 );
		return base64String & padding;
	}

	/**
	* Decode a url encoded base64 string
	* @value The string to manipulate
	*/
	private function base64UrlDecode( required string value ){
		return toString( toBinary( base64UrlUnescape( arguments.value ) ) );
    }
    
    /**
	* Converts epoch datetime to local date
	* @epoch Seconds from Jan 1, 1970
	*/
	private function epochTimeToLocalDate( required numeric epoch ){
		return createObject( "java", "java.util.Date" ).init( epoch* 1000 );
    }

    /**
    * Generates an epoch datetime value from the given datetime string / timestamp
    * 
    * @datetime The datetime value to convert into an epoch
    */
    private string function generateEpochTime( required string datetime ){
        var startDate = createdatetime( '1970','01','01','00','00','00' );
        var givenDateTime = dateConvert( 'local2utc', arguments.datetime );
        return dateDiff( 's', startDate, givenDateTime );
    }
    
    /**
    * Strips the comments and breaks from the private key
    */
    private string function getRealPK(){
        var strPk = getCredentialsJSON()[ 'private_key' ];
        strPk = strPk.replaceAll( "-----END PRIVATE KEY-----", "" );
        strPk = strPk.replaceAll( "-----BEGIN PRIVATE KEY-----", "" );
        strPk = strPk.replaceAll( "\n", "" );
        return strPk;
    }

    /**
    * Encodes the JWT
    * @payload The structure containing the data to encrypt
    * @algorithm The algorithm to use when encoding. Defaults to 'RS256'
    */
    private function encode( required struct payload ){
        var segments = '';
        // Add Header - typ and alg fields
        segments = appendSegment( segments, {
            "typ" =  "JWT",
            "alg" = "RS256"
        } );
        // Add payload
        segments = appendSegment( segments, arguments.payload );
        // Add signature
        segments = listAppend( segments, signSHA256RSA( segments ), "." );
        return segments;
    }

    /**
    * Helper method to append the struct data to the segment list when building the JWT
    * 
    * @list The list to append the data
    * @data The data to be added to the list
    */
    private function appendSegment(
        required string list,
        required struct data
    ){
        var strList = arguments.list;
        var stuData = arguments.data;
        return listAppend( strList, base64UrlEscape( toBase64( serializeJSON( stuData ) ) ), "." );
    }

    /**
    * Decodes the given JWT
    */
    private function decode( required string token ){
        if( listLen( arguments.token, "." ) != 3 ){
            throw( type="Invalid Token", message="Token should contain 3 segments" );
        }
        var header    = deserializeJSON( base64UrlDecode( listGetAt( arguments.token, 1, "." ) ) );
        var payload   = deserializeJSON( base64UrlDecode( listGetAt( arguments.token, 2, "." ) ) );
        var signature = listGetAt( arguments.token, 3, "." );
        // Verify claims
        if( structKeyExists( payload, "exp" ) ){
            if( epochTimeToLocalDate( payload.exp ) < now() ){
                throw( type="Invalid Token", message="Signature verification failed: Token expired" );
            }
        }
        if( structKeyExists( payload, "nbf" ) && epochTimeToLocalDate( payload.nbf ) > now() ){
            throw( type="Invalid Token", message="Signature verification failed: Token not yet active" );
        }
        if( structKeyExists( payload, "iss" ) && getCredentialsJSON()[ 'client_email' ] != "" && payload.iss != getCredentialsJSON()[ 'client_email' ] ){
            throw( type="Invalid Token", message="Signature verification failed: Issuer does not match" );
        }
        if( structKeyExists( payload, "aud" ) && getTokenEndpoint() != "" && payload.aud != getTokenEndpoint() ){
            throw( type="Invalid Token", message="Signature verification failed: Audience does not match" );
        }
        // Verify signature
        var signInput = listGetAt( arguments.token, 1, "." ) & "." & listGetAt( arguments.token, 2,"." );
        if( signature != signSHA256RSA( signInput, 'RSA256' ) ){
            throw( type="Invalid Token", message="Signature verification failed: Invalid key" );
        }
        return payload;
    }


	/**
	* Get the current CFML Engine
	*/
	private string function getEngine() {
		var engine = "ADOBE";

		if ( server.coldfusion.productname eq "Lucee" ){
			engine = "LUCEE";
		}

		return engine;
	}

}