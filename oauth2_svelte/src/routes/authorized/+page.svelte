<script>
  import {Buffer} from "buffer";
  import {page} from "$app/stores";
  import {goto} from '$app/navigation';

  const code = $page.url.searchParams.get('code');
  const client = 'client';
  const secret = 'secret';
  const headers = new Headers();
  headers.append('Content-type', 'application/json');
  headers.append('Authorization', `Basic ${Buffer.from(`${client}:${secret}`).toString('base64')}`);

  const verifier = sessionStorage.getItem('codeVerifier');

  const initialUrl = 'http://127.0.0.1:8080/oauth2/token?client_id=client&redirect_uri=http://127.0.0.1:3000/authorized&grant_type=authorization_code';
  const url = `${initialUrl}&code=${code}&code_verifier=${verifier}`;

  fetch(url, {
    method: 'POST',
    mode: 'cors',
    headers
  }).then(async (response) => {
    const token = await response.json();
    if (token?.id_token) {
      sessionStorage.setItem('id_token', token.id_token);
      goto('/');
    }
  }).catch((err) => {
    console.log(err);
  })

</script>