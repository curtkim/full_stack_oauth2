//GET  http://localhost:8080/oauth2/authorize?response_type=code&client_id=client&scope=openid&redirect_uri=http://127.0.0.1:3000/authorized&code_challenge=4OwUVqBrOJEf0UGP2-qYO3X-zNPXL_bmIxMffD1ZjxA&code_challenge_method=S256
//302  http://localhost:8080/login
//POST http://localhost:8080/login form username= password= _csrf=
//302  http://127.0.0.1:8080/oauth2/authorize?response_type=code&client_id=client&scope=openid&redirect_uri=http://127.0.0.1:3000/authorized&code_challenge=1Bhl_ay02tio4qt46cvuZ8ZgbWrQXRRBFxqjwszSkKk&code_challenge_method=S256&continue
//302  http://127.0.0.1:3000/authorized?code=ALNuy9EH3twlj8l71LpwuCLTo1HL_ZyD9a93MzqB7EPl8Hx6s_RlYaCxUYHTI-8VUCYVRpQtNfrl4IXLHNMt-31eyQqC4k5AtPKurRDE5dPl1ES3XfXvAVPVbdRZaUeS
//302  http://127.0.0.1:3000/authorized?code=wrn6ZUEXPxBaYYAKuR1uDlsLbXIif5X4EggAN7vqLOgx3IAPv-CE72K9I0LSuKxjYSkBof5pz2ZlRg1rIT4sXLTIpiMoMd9uMvMoJXzIA8napTQqauXcAob6jaSagP1z
//POST http://localhost:8080/oauth2/token?client_id=client&redirect_uri=http://127.0.0.1:3000/authorized&grant_type=authorization_code&code=wrn6ZUEXPxBaYYAKuR1uDlsLbXIif5X4EggAN7vqLOgx3IAPv-CE72K9I0LSuKxjYSkBof5pz2ZlRg1rIT4sXLTIpiMoMd9uMvMoJXzIA8napTQqauXcAob6jaSagP1z&code_verifier=gpXXN2LgKT_ed_3HPrVgOwgP7j8rI4tThrthfMbcH6s
/*
{
    "access_token": "eyJraWQiOiI4MWE4MDQ4Ny1lMTY4LTRjZjgtODU2ZC1hNGVkZDI5YjA2ZDgiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiaWxsIiwiYXVkIjoiY2xpZW50IiwibmJmIjoxNjk2MjU5NTc5LCJzY29wZSI6WyJvcGVuaWQiXSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiZXhwIjoxNjk2MjU5ODc5LCJpYXQiOjE2OTYyNTk1Nzl9.X9pXTBPEKZ86wcv7Lf_b7IifH305lXR7rKBckq_KVnSbTt-Oqe_gLX6UrJeDlKy-1rh8rn5PqfvGO89QQPlqE3YHpgEGezhzzt6d1l0jy0gkc0BWfM4QdzPQ0hHCGqr1HPsFm7CbZqKflms1Xbwnh0TsxDtjDfyk-PeY6A9MS2l2ZmAiNmoteI2fLBQebn_bdyxlqzso8dacv5xVXYD3Hud_PgyvjQ9uvgiF0MGnF0qsIvvQTN_Lui-KOFJadh6Bg0htnbX_d_ElmswYiotaf9qnMTBwwMigeE9oj8cMkXhNomJMjU7PeYOFshmAPsfSf7tAabZmluPjQixvpJ5MGA",
    "refresh_token": "zIbtOp_QYE29K3rGCTGwyJOZqlW6vVPjeCfgKJneGY6SrFOedBTCCRZVUbD-7bFapoAAMgKd-2A5E87LhBm0MQq0WvcwL-iLeao76sEUIzQ8_utHUMO9No0n0F9rz7ur",
    "scope": "openid",
    "id_token": "eyJraWQiOiI4MWE4MDQ4Ny1lMTY4LTRjZjgtODU2ZC1hNGVkZDI5YjA2ZDgiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAiLCJzdWIiOiJiaWxsIiwiYXVkIjoiY2xpZW50IiwiZXhwIjoxNjk2MjYxMzc5LCJpYXQiOjE2OTYyNTk1NzksImF6cCI6ImNsaWVudCJ9.bzf5TeQE9Lm8YksrHMZohI99nZiWiRI-W8jaxSTxtGE37LjVot_gEaTHEHMhAPRsDGVMadNebnUSleUKpoRSxbkyamYjsqX8xYa_jRTofSsHuvqdRcPyrvdJut54YbdO08MixrVkCih0au0wLzqFPDiMgTwi9ylE9rSHrSOLL4LvmnPe4gxf_yUdgYSUYkFduFM4XzvOHzJ_OkSw1tgK45RldIlnxljDLDf9-CRJBfBG41WmsFi99PO-xMiZu3KUGVbhvec59qb32pgddVWazTtvecqMwjhyKi9ddrjSR312kZp1hYJtOx-XeKcZKUu6mm06TMfoo24gzt5We_8Hxw",
    "token_type": "Bearer",
    "expires_in": 299
}
*/