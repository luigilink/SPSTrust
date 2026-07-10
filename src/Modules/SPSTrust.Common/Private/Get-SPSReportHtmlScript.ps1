function Get-SPSReportHtmlScript {
    <#
        .SYNOPSIS
        Returns the vanilla-JavaScript block that makes the trust matrix table interactive.

        .DESCRIPTION
        Operates on the static <table id="trust-matrix"> rendered server-side by
        Export-SPSTrustReport (so the status "pills" are real HTML). It wires:

        - a search box (id="matrix-search") that shows/hides rows by matching text in
          any cell (case-insensitive), and
        - clickable column headers that sort the visible rows. Sorting uses each cell's
          textContent, which for status columns is the pill label (Present/Absent/N/A).

        The row count indicator (id="matrix-info") is updated on every filter. No
        external dependency (works offline on a SharePoint server).
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param ()

    $js = @'
(function(){
  var table = document.getElementById('trust-matrix');
  if (!table) { return; }
  var tbody = table.tBodies[0];
  var search = document.getElementById('matrix-search');
  var info = document.getElementById('matrix-info');
  var allRows = Array.prototype.slice.call(tbody.rows);
  var sortCol = -1, sortDir = 1;

  function cellText(row, i){
    var c = row.cells[i];
    return c ? (c.textContent || '').trim().toLowerCase() : '';
  }

  function applyFilter(){
    var q = (search && search.value || '').trim().toLowerCase();
    var shown = 0;
    allRows.forEach(function(r){
      var match = !q || (r.textContent || '').toLowerCase().indexOf(q) !== -1;
      r.style.display = match ? '' : 'none';
      if (match) { shown++; }
    });
    if (info) { info.textContent = shown + ' / ' + allRows.length + ' rows'; }
  }

  function applySort(col){
    if (sortCol === col) { sortDir = -sortDir; } else { sortCol = col; sortDir = 1; }
    var rows = allRows.slice();
    rows.sort(function(a,b){
      var x = cellText(a, col), y = cellText(b, col);
      if (x < y) { return -1 * sortDir; }
      if (x > y) { return 1 * sortDir; }
      return 0;
    });
    rows.forEach(function(r){ tbody.appendChild(r); });
  }

  var headers = table.tHead ? table.tHead.rows[0].cells : [];
  Array.prototype.forEach.call(headers, function(th, i){
    th.addEventListener('click', function(){ applySort(i); });
  });

  if (search) { search.addEventListener('input', applyFilter); }
  applyFilter();
})();
'@

    return "<script>$js</script>"
}
