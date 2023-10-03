/** @type {import('./$types').PageLoad} */
export async function load({fetch}) {
  const token = sessionStorage.getItem('id_token');
  const headers = new Headers();
  headers.set('Content-type', 'plain/text');
  headers.set('Authorization', `Bearer ${token}`);
  const url = 'http://127.0.0.1:9000/demo';
  const text = (await fetch(url, {
      method: 'GET',
      mode: 'cors',
      headers
    })).text();

  return {
    text
  };
}