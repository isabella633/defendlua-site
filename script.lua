const params = new URLSearchParams(window.location.search);
const encoded = params.get('c');
if(encoded){
    const code = decodeURIComponent(escape(atob(encoded)));
    document.open();
    document.write(`<pre>${code}</pre>`);
    document.close();
}
