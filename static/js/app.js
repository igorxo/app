$(function () {
    // Start # Enable popovers to work
    $('[data-toggle="popover"]').popover();
    $('.popover-dismiss').popover({trigger: 'focus'});
    // End   # Enable popovers to work
});

function go() {
    console.log("INSIDE GO");
    var form = $("#licenseForm")[0];
    var data = new FormData(form);
    $.ajax({
        type: "POST",
        enctype: "multipart/form-data",
        processData: false,  // Important!
        contentType: false,
        cache: false,
        data: data,
        url: 'uploadlicense',
        success: function (result) {
            if (result == "OK") {
                window.location.replace('index');
            } else {
                alert(result);
            }
        },
        error: function (e) {
            alert("Error: " + e.message)
        }
    });
}



$(document).ready(function(){
    $('#authTokenForm').on('submit', function(e){
        e.preventDefault();
        $.post("save_auth", $('#authTokenForm').serialize(), function(result) {
            if (!result) {
                $('#authTokenField').removeClass('is-valid');
                $('#authTokenField').addClass('is-invalid');
            } else {
                $('#authTokenField').removeClass('is-invalid');
                $('#authTokenField').addClass('is-valid');
                window.location.replace('index');
            }
        });
    });
    $('#licenseForm').on('submit', function(e){
        console.log("INSIDE SUBMIT");
        e.preventDefault();
        var form = $("#licenseForm")[0];
        var data = new FormData(form);
        $.ajax({
            type: "POST",
            enctype: "multipart/form-data",
            processData: false,  // Important!
            contentType: false,
            cache: false,
            data: data,
            url: 'uploadlicense',
            success: function (result) {
                if (result == "OK") {
                    window.location.replace('index');
                } else {
                    alert(result);
                }
            },
            error: function (e) {
                alert("Error: " + e.message)
            }
        });
    });

    $('#vtKeysForm').on('submit', function(e){
        e.preventDefault();
        $.post("save_vt_keys", $('#vtKeysForm').serialize(), function(result) {
            if (!result) {
                $('#vtKeysField').removeClass('is-valid');
                $('#vtKeysField').addClass('is-invalid');
            } else {
                $('#vtKeysField').removeClass('is-invalid');
                $('#vtKeysField').addClass('is-valid');
            }
            $('#vtKeysField').focus();
        });
    });
    $('#vtEnginesForm').on('submit', function(e){
        e.preventDefault();
        $.post("save_vt_engines", $('#vtEnginesForm').serialize(), function(result) {
            if (!result) {
                $('#vtEnginesClass1Field').removeClass('is-valid');
                $('#vtEnginesClass1Field').addClass('is-invalid');
            } else {
                $('#vtEnginesClass1Field').removeClass('is-invalid');
                $('#vtEnginesClass1Field').addClass('is-valid');
            }
            $('#vtEnginesClass1Field').focus();
        });
    });
    $('#advancedForm').on('submit', function(e){
        e.preventDefault();
        $.post("save_advanced", $('#advancedForm').serialize(), function(result) {
            if (!result) {
                $('#maxHashField').removeClass('is-valid');
                $('#maxHashField').addClass('is-invalid');
                $('#maxRateField').removeClass('is-valid');
                $('#maxRateField').addClass('is-invalid');
            } else {
                $('#maxHashField').removeClass('is-invalid');
                $('#maxHashField').addClass('is-valid');
                $('#maxRateField').removeClass('is-invalid');
                $('#maxRateField').addClass('is-valid');
            }
        });
    });
});
