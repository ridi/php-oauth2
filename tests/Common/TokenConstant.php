<?php declare(strict_types=1);

namespace Ridibooks\Test\OAuth2\Common;

class TokenConstant
{
    const USER_IDX = 2803050;
    const USERNAME = 'ridioauth2test';
    const CLIENT_ID = 'iax7OcCuYJ8Su5p9swjs7RNosL7zYZ4zdV5xyHVx';
    const CLIENT_SECRET = 'vk31iDFzVM1EKQySvkp46TUNjWn9Bvc1wv7CLSwEWzAUDz5GA3iN0QjGktVXi53KCHxIcfq3V62q9aSQkWzB1zx8Um6OWYO4nEqtJYj4uPHnhjDKW7tV4zGeW9yygvZx';
    const SECRET = 'secret';
    const KEY_FILE = __DIR__ . '/../resources/key.pub';

    const TOKEN_VALID = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJTOTk5In0.eyJzdWIiOiJyaWRpb2F1dGgydGVzdCIsInVfaWR4IjoyODAzMDUwLCJleHAiOjIwNDkzNjY0MTEsImNsaWVudF9pZCI6ImFzZmVpaDI5c252OGFzMjEzaSIsInNjb3BlIjoiIn0.k0A0RqtY3tB8VdieGYDTVk1COliRkJzB-PIcCcQkVUEMr5VXBVb8fpEkNcMZD0_eHqo2gJcHYcCRbD6QCxEVNBVJpXUkk2BNc3WMWqLoAq1JnP1JsKGnIXNJrbMII1XVYm1-T0ObUDuK15HIY1b667WURaHOnZ7vrrArQfrRuQo_qWWk5bbnU3WxT_5n7n-BaRRE5rGs8hYbfDAULRT98RrfUPWXdFiyTllwJDLcvySdCp7Qq47PEIDbp6_WOnfjkpMuVGikfdoaZEuq3W1ZHa6HwpJDSN8i7CNZwvotGDgOu29_Jn_D4sZeSe6s9FnihA66AiJPzHycN_gjrWHPQQ';
    const TOKEN_EXPIRED = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJTOTk5In0.eyJzdWIiOiJ0ZXN0dXNlciIsInVfaWR4IjoxMjMxMjMsImV4cCI6MTU3NjIwMDA5MSwiY2xpZW50X2lkIjoiYXNmZWloMjlzbnY4YXMyMTNpIiwic2NvcGUiOiJhbGwifQ.FqN97j4pxyH3xmgdw1ulitiFfS2HgSp4LRdqLOA7Bx77LCIqhbQUnw64yIfmjVnLoqz5eiY4Ds56_I1pBoJdjdWl5CSa7b_i6CAQLmDiq3k-X0OPH4-grnnb9IfWtKniDZ3vTj2wYCUrrV9GphNDk95E0cn5D6gSX1en4NcpahM-Tyse72NmhJV6h0P9OhxL4rNl58bvStg8ZUPctBEwa1ct6B8jTNft6FgHd-0S-IIrDeVXvmghnKXQhiiocBPWhtyI4Nf_ozojfjoqcECJ9dm7hYtR2jgCYp__z7reWWH0Y7Hw6wyFsWrZUme8Orf53S2wrJAWkjJ9jl4izrhj5g';
    const TOKEN_INVALID_PAYLOAD = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJTOTk5In0.eyJzdWIyIjoidGVzdHVzZXIiLCJ1X2lkeCI6MTIzMTIzLCJleHAiOjIwNDkyNjQwMTAsImNsaWVudF9pZCI6ImFzZmVpaDI5c252OGFzMjEzaSIsInNjb3BlIjoiYWxsIn0.IeMtiUzMWY8hzc6Tb-OJ5qsFkXZWOQBN1eMp5lzUmFqDrIrJgK_hHtLImuuC5d_uw8CO6EwURgvWReCQ2_JaYomKDVZ-5lQ92EFTjsa_5iMfmesb7ygSqEBe4ALP63f5CHh59_sznUuLgPvdyY5XJ3zHtKKBV-X2Gpb0r6aUP394kBJ2uvYj5y13p3VhKlKs7zkyHWFSZrxMjbwqN-PnvfakRhDSDfn9O8SCwu4k0pIkARGiRKsypgmmPqsYDx0vL6rQgVrcDhceHKgOT10lGVM-nHEGd_qM5t-RJVeoBiaskU_v-T1oKt6MK5DDcyt1PdGvzeQx6EXfyj91t1Ty_Q';
    const TOKEN_INVALID_SIGNATURE = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJTOTk5In0.eyJzdWIyIjoidGVzdHVzZXIiLCJ1X2lkeCI6MTIzMTIzLCJleHAiOjIwNDkyNjQwMTAsImNsaWVudF9pZCI6ImFzZmVpaDI5c252OGFzMjEzaSIsInNjb3BlIjoiYWxsIn0.IeMtiUzMWY8hzc6Tb-OJ5qsFkXZWOQBN1eMp5lzUmFqDrIrJgK_hHtLImuuC5d_uw8CO6EwURgvWReCQ2_JaYomKDVZ-5lQ92EFTjsa_5iMfmesb7ygSqEBe4ALP63f5CHh59_sznUuLgPvdyY5XJ3zHtKKBV-X2Gpb0r6aUP394kBJ2uvYj5y13p3VhKlKs7zkyHWFSZrxMjbwqN-PnvfakRhDSDfn9O8SCwu4k0pIkARGiRKsypgmmPqsYDx0vL6rQgVrcDhceHKgOT10lGVM-nHEGd_qM5t-RJVeoBiaskU_v-T1oKt6MK5DDcyt1PdGvzeQx6EXfyj9_Q';
    const TOKEN_HAS_NO_SCOPE = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJTOTk5In0.eyJzdWIiOiJ0ZXN0dXNlciIsInVfaWR4IjoxMjMxMjMsImV4cCI6MjA0OTI2NTQ2NiwiY2xpZW50X2lkIjoiYXNmZWloMjlzbnY4YXMyMTNpIiwic2NvcGUiOiIifQ.FyHKwa-98jvLdFeJuo2gInFW0ZtYbH01yr4byyXPTqDnHU2X39HgKTwLdmipeQvig57cGysA2PxIrj8yguH1emOjvZbzWZVd3R1gaCwocCNwSsWppRenLHKKCHnWP33ezC2pI5jon9Kr3Q0Y1zh2q1uPs6zmvtk9QzjZNeBFyJ3iOIJMoSWUvVAX4olNyDYdYTGjqBAAWB0Y62Ief4x4I3rmNX2yA_Sgbv1R7G0Y_SNik6jbBaQ_ThVK_QxV3B2Fl7-LNILBWQwSiSZBvBjjduvqDqJxxGrPzy_CBaElch7oaw5fDjBFIUbMjHizZMbLVaQxBCn0kP1ln4poEEmg5Q';
    const TOKEN_EMPTY = '';
    const TOKEN_UNKNOWN_USER = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1bmtub3duIiwidV9pZHgiOjAsImV4cCI6MTkzMTEwMzQ4NSwiY2xpZW50X2lkIjoiaWF4N09jQ3VZSjhTdTVwOXN3anM3Uk5vc0w3ellaNHpkVjV4eUhWeCIsInNjb3BlIjoiYWxsIn0.K5j1G3jIrEj6S0XyMXSoa3K3HOgwunjI3-ptyT0q4vE';

    const KID_TOKEN_VALID = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImtpZDEifQ.eyJzdWIiOiJ0ZXN0dXNlciIsInVfaWR4IjoxMjMxMjMsImV4cCI6MjA0OTM1MjA4OCwiY2xpZW50X2lkIjoiYXNmZWloMjlzbnY4YXMyMTNpIiwic2NvcGUiOiIifQ.1QLClSdNj3ZdXkiEqWUatyE07hwVNzs2vqof2YIyO9sl0I_DWN0fbhf-VkyQ6xa2w31vFTCzIzk3gL2Swsgp11AXBWw8DYmqorFmPqGVUP_pl2QoY6BjoEB4WPLQRNIvHs0Dj8RqgzWPX17j9B1Dz6n2XUmYPvb2HINR5yJ_a9iBvjLSWjtM0u-Gul3aBq24H-7kYH11bp2PFdyc7QlnLT0OMBtsj1APlEgRQspxitOGR64JiycdhTK8wRCSYA0bYUCwmhWr0I1vdtqnT3uAQ7ENgA9RFiTL0hXXgYEjm_Wvs9pbFTgeGyOhPfipgq0VtPYLeYZPEABm9LSurngD9A';
    const KID_TOKEN_INVALID_KID = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImtpZHdyb25nd3JvbmcifQ.eyJzdWIiOiJ0ZXN0dXNlciIsInVfaWR4IjoxMjMxMjMsImV4cCI6MjA0OTM1NDE0OSwiY2xpZW50X2lkIjoiYXNmZWloMjlzbnY4YXMyMTNpIiwic2NvcGUiOiIifQ.tQEGUDbUHr6_S9RrnjJnxzbA2J7n4LcWEQTKByshDe1r6rwc7QxvjJGGfYE-MTlou1Ar68CNJdHIZNCWwJfgLRcKEapLe9KmDw-W9FogQiW081KOTemBSgaWV80cqhvmELVTH3K87CPkYaw-IaUw9NNNwCX22ngcvmoIbdEKCe0rt6gFNIwwrDPu5WB-uyVNHktf2E66GjIspbsvAMsXEseHQ3dD62pZq7A4tOhfR0HXDFaKM-g3nGKl4hgYs6zBxGIgw4Hu2Gt3GHyJd8lDtxEjdtjUxMgMKtvTuIujdqOP7UChWzh5Dqu0jnIcYlkHXXWxjWHyE8ITEwgOPs9OMQ';
    const KID_TOKEN_WITHOUT_KID = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0dXNlciIsInVfaWR4IjoxMjMxMjMsImV4cCI6MjA0OTM1Mzg0NCwiY2xpZW50X2lkIjoiYXNmZWloMjlzbnY4YXMyMTNpIiwic2NvcGUiOiIifQ.kyxxx5nSKt8-1cTqBmCOIEDxa7yCk39d3DOfcJKQPb1ZMdltG3_UmtlJhIL4fBIIoDQtHkYv1Mjb4XqlK0r_637DvCEFYcHSL_M8ATYeqYUVa-Npd0i_GzJTKZhcaHYEk-Va6sDXGECoFlVmrC_NcDWF7m3lKUEGoTb7IBxwgUv_xZnxPAjRcKWdG6YuNwuUFK3BiWFvxJMEHe6tGinSty15ZdXjDkhsq_YLa0F78yIItdZ_uqpCoo5BTWxUSxGjNQdppkGBXAdPNr1Y2LRS-TFzl2N4QnHoSQvvduNQ1oTdrSjeMTx6Hkm80Gzz3QEUhCkjEEMRuDgnrVCFv2nBHQ';
}
