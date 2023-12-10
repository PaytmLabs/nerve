$('#dataTables-vulnerabilities').DataTable({
    responsive: true,
    pageLength: 20,
    lengthChange: false,
    searching: true,
    ordering: true,
    "language": {
       "search": gettext("Search:"),
       "paginate": {
           "first": gettext("First"),
           "previous": gettext("Previous"),
           "next": gettext("Next"),
           "last": gettext("Last")
       },
       "emptyTable": gettext("No vulnerabilities have been found.")
    }
});
