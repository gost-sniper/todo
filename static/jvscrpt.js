function updateTodo(id){
    var username = $("#usrnm").text().toLowerCase();

    if ($('#'+id).is(":checked"))
    {
      $.post( "/user/"+username+ "/complete/" + id, function( data ) {
          $("#todo-"+id).addClass("btn-success")
          $("#todo-"+id).removeClass("btn-warning")
        });
    }
    else{
        $.post( "/user/"+username+"/uncomplete/" + id, function( data ) {
            $("#todo-"+id).removeClass("btn-success")
          $("#todo-"+id).addClass("btn-warning")
        });
    }
}
function removeTodo(id){
    var username = $("#usrnm").text().toLowerCase();

    $.post( "/user/"+username+"/remove/" + id, function( data ) {
        location.reload(true);
    });
}