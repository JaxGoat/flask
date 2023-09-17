$(function () {
    $("#search-input").autocomplete({
        source: function (request, response) {
            var list = [];
            list = words.filter(function (word) {
                return word.indexOf(request.term) === 0 || word.toLowerCase().indexOf(request.term) === 0;
            }).slice(0, 15);
            response(list);
        },
    });
});