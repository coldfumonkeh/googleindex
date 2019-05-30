<cfset objGoogleIndex = new GoogleIndex( expandPath( './credentials.json' ) ) />
<cfset objGoogleIndex.getAccessToken() />
<cfset response = objGoogleIndex.updateURL( 'https://www.monkehworks.com' ) />
<cfdump var="#response#" />