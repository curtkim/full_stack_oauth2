<script>
  async function getDemo(token) {
    const headers = new Headers();
    headers.set('Content-type', 'plain/text');
    headers.set('Authorization', `Bearer ${token}`);
    const url = 'http://127.0.0.1:9000/demo';
    const res = await fetch(url, {method: 'GET', mode: 'cors', headers })

    if(res.ok) {
      return res.text();
    }
    else{
      console.log(res.status, res.statusText)
      throw new Error(res.status)
    }
  }

  const token = sessionStorage.getItem('id_token');
  let promise = getDemo(token)

</script>

<h1>Protected</h1>
{#await promise}
	<!-- promise is pending -->
	<p>waiting for the promise to resolve...</p>
{:then value}
	<!-- promise was fulfilled -->
	<p>The value is {value}</p>
{:catch error}
	<!-- promise was rejected -->
	<p>Something went wrong: {error.message}</p>
{/await}