<script>
  import { generateCodeChallenge, generateCodeVerifier } from '$lib/pkce';
  function login() {
    const verifier = generateCodeVerifier();
    sessionStorage.setItem('codeVerifier', verifier);

    const codeChallenge = generateCodeChallenge();
    sessionStorage.setItem('codeChallenge', codeChallenge);

    const link = `http://127.0.0.1:8080/oauth2/authorize?response_type=code&client_id=client&scope=openid&redirect_uri=http://127.0.0.1:3000/authorized&code_challenge=${codeChallenge}&code_challenge_method=S256`;
    window.location.href = link;
  }
</script>
<button on:click={login}>login</button>