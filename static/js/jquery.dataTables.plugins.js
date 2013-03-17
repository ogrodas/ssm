

 $.fn.dataTableExt.oApi.fnReloadAjax = function(oSettings, sNewSource) {
    oSettings.sAjaxSource = sNewSource;
    this.fnClearTable(this);
    this.oApi._fnProcessingDisplay(oSettings, true );
    var that = this;

    $.getJSON(oSettings.sAjaxSource, null, function(json){
    /* Got the data - add it to the table */
        for (var i=0; i<json.aaData.length; i++) {
            that.oApi._fnAddData(oSettings, json.aaData[i]);
        }
        oSettings.aiDisplay = oSettings.aiDisplayMaster.slice();
        that.fnDraw(that);
        that.oApi._fnProcessingDisplay(oSettings, false);
    });
}



/*
 * Function: fnGetDisplayNodes
 * Purpose:  Return an array with the TR nodes used for displaying the table
 * Returns:  array node: TR elements
 *           or
 *           node (if iRow specified)
 * Inputs:   object:oSettings - automatically added by DataTables
 *           int:iRow - optional - if present then the array returned will be the node for
 *             the row with the index 'iRow'
*/
$.fn.dataTableExt.oApi.fnGetDisplayNodes = function ( oSettings, iRow )
{
var anRows = [];
if ( oSettings.aiDisplay.length !== 0 ){
    if ( typeof iRow != 'undefined' ) {
        return oSettings.aoData[ oSettings.aiDisplay[iRow] ].nTr;
    }
    else {
        for ( var j=oSettings._iDisplayStart ; j<oSettings._iDisplayEnd ; j++ ){
            var nRow = oSettings.aoData[ oSettings.aiDisplay[j] ].nTr;
            anRows.push( nRow );
        }
    }
}
return anRows;
};

