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

//    const TOKEN_VALID = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJTMDAwIn0.eyJzdWIiOiJ0ZXN0dXNlciIsInVfaWR4IjoxMjMxMjMsImV4cCI6MTU3NjAzMDQ0OCwiY2xpZW50X2lkIjoiYXNmZWloMjlzbnY4YXMyMTNpIiwic2NvcGUiOiJhbGwifQ.alWFlzbkR-z5vG6H7-WMli9QJ2ivAYTp1zncaqcZ6c7qbxuKueDfeUxhKB-MW_J9F7Zt7hSnDhRqN_4Nvrv-Ar5c96RUr2vFhsPAJ7Hyte_FBjrKKZOQqMAXGdtmXvnKlVrcmpyWLdOTq21T54x4h9P3XppJcDy-yr7SvAbkw4AE34nGQEMPcotHK5XaI3qSd2VvySrXroV8iOG3W3mM9nF4AdFtIFe670qfkjkPip0GDXiox0EcTonZp28pR9LnhanGQogxs1vXHsMEfXbFP7lw1zZP7B6X4AITkdqNGAZRi64-i272KUHIPTfOrwbHixryoT1yrJLAYWDN-mTorw';
    const TOKEN_VALID = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJTOTk5In0.eyJzdWIiOiJ0ZXN0dXNlciIsInVfaWR4IjoxMjMxMjMsImV4cCI6MjA0OTI0NjY5OCwiY2xpZW50X2lkIjoiYXNmZWloMjlzbnY4YXMyMTNpIiwic2NvcGUiOiJhbGwifQ.kV10guQ0t8xAuf6VC4naIUlJL1MPi1tszzjTWSNsCMtJiFoS-jBr456fO1_4cR1LcVXg3edCBPrUGPbIe5gpWxqhR4mgGiwwflssqEsjR2bG_rS26JFBDte0FP189Ucb8SNKrCAVV4TYDIyDa8m2tsdthx8A4GmLFWqzFc2mNBJUjZ4VwYgTs3-Weo1DynfcHw0soJlO98ADuqZpfEornMTepLHx6dsl8EjiwA3cWlhyS9mxmzLRhBaQcx9Grz54MxSIrVpu2axiho0mNSA98OAsf7oxTLA6BcbLi64a9Npx3wNuQY9tCyB5UPuDtBYytmITsohBQyGb2nz9ou9GWA';
//    const TOKEN_EXPIRED = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJyaWRpb2F1dGgydGVzdCIsInVfaWR4IjoyODAzMDUwLCJleHAiOjE1MjExMDM0ODUsImNsaWVudF9pZCI6ImlheDdPY0N1WUo4U3U1cDlzd2pzN1JOb3NMN3pZWjR6ZFY1eHlIVngiLCJzY29wZSI6ImFsbCJ9.0IkMVrnHc6Z6HznxjURS3vvKd-4aF58pbmqgP8rTyYs';
    const TOKEN_EXPIRED = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJTOTk5In0.eyJzdWIiOiJ0ZXN0dXNlciIsInVfaWR4IjoxMjMxMjMsImV4cCI6MTU3NjIwMDA5MSwiY2xpZW50X2lkIjoiYXNmZWloMjlzbnY4YXMyMTNpIiwic2NvcGUiOiJhbGwifQ.FqN97j4pxyH3xmgdw1ulitiFfS2HgSp4LRdqLOA7Bx77LCIqhbQUnw64yIfmjVnLoqz5eiY4Ds56_I1pBoJdjdWl5CSa7b_i6CAQLmDiq3k-X0OPH4-grnnb9IfWtKniDZ3vTj2wYCUrrV9GphNDk95E0cn5D6gSX1en4NcpahM-Tyse72NmhJV6h0P9OhxL4rNl58bvStg8ZUPctBEwa1ct6B8jTNft6FgHd-0S-IIrDeVXvmghnKXQhiiocBPWhtyI4Nf_ozojfjoqcECJ9dm7hYtR2jgCYp__z7reWWH0Y7Hw6wyFsWrZUme8Orf53S2wrJAWkjJ9jl4izrhj5g';
    const TOKEN_INVALID_PAYLOAD = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJTOTk5In0.eyJzdWIyIjoidGVzdHVzZXIiLCJ1X2lkeCI6MTIzMTIzLCJleHAiOjIwNDkyNjQwMTAsImNsaWVudF9pZCI6ImFzZmVpaDI5c252OGFzMjEzaSIsInNjb3BlIjoiYWxsIn0.IeMtiUzMWY8hzc6Tb-OJ5qsFkXZWOQBN1eMp5lzUmFqDrIrJgK_hHtLImuuC5d_uw8CO6EwURgvWReCQ2_JaYomKDVZ-5lQ92EFTjsa_5iMfmesb7ygSqEBe4ALP63f5CHh59_sznUuLgPvdyY5XJ3zHtKKBV-X2Gpb0r6aUP394kBJ2uvYj5y13p3VhKlKs7zkyHWFSZrxMjbwqN-PnvfakRhDSDfn9O8SCwu4k0pIkARGiRKsypgmmPqsYDx0vL6rQgVrcDhceHKgOT10lGVM-nHEGd_qM5t-RJVeoBiaskU_v-T1oKt6MK5DDcyt1PdGvzeQx6EXfyj91t1Ty_Q';
    const TOKEN_INVALID_SIGNATURE = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJTOTk5In0.eyJzdWIyIjoidGVzdHVzZXIiLCJ1X2lkeCI6MTIzMTIzLCJleHAiOjIwNDkyNjQwMTAsImNsaWVudF9pZCI6ImFzZmVpaDI5c252OGFzMjEzaSIsInNjb3BlIjoiYWxsIn0.IeMtiUzMWY8hzc6Tb-OJ5qsFkXZWOQBN1eMp5lzUmFqDrIrJgK_hHtLImuuC5d_uw8CO6EwURgvWReCQ2_JaYomKDVZ-5lQ92EFTjsa_5iMfmesb7ygSqEBe4ALP63f5CHh59_sznUuLgPvdyY5XJ3zHtKKBV-X2Gpb0r6aUP394kBJ2uvYj5y13p3VhKlKs7zkyHWFSZrxMjbwqN-PnvfakRhDSDfn9O8SCwu4k0pIkARGiRKsypgmmPqsYDx0vL6rQgVrcDhceHKgOT10lGVM-nHEGd_qM5t-RJVeoBiaskU_v-T1oKt6MK5DDcyt1PdGvzeQx6EXfyj9_Q';
    const TOKEN_HAS_NO_SCOPE = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJTOTk5In0.eyJzdWIiOiJ0ZXN0dXNlciIsInVfaWR4IjoxMjMxMjMsImV4cCI6MjA0OTI2NTQ2NiwiY2xpZW50X2lkIjoiYXNmZWloMjlzbnY4YXMyMTNpIiwic2NvcGUiOiIifQ.FyHKwa-98jvLdFeJuo2gInFW0ZtYbH01yr4byyXPTqDnHU2X39HgKTwLdmipeQvig57cGysA2PxIrj8yguH1emOjvZbzWZVd3R1gaCwocCNwSsWppRenLHKKCHnWP33ezC2pI5jon9Kr3Q0Y1zh2q1uPs6zmvtk9QzjZNeBFyJ3iOIJMoSWUvVAX4olNyDYdYTGjqBAAWB0Y62Ief4x4I3rmNX2yA_Sgbv1R7G0Y_SNik6jbBaQ_ThVK_QxV3B2Fl7-LNILBWQwSiSZBvBjjduvqDqJxxGrPzy_CBaElch7oaw5fDjBFIUbMjHizZMbLVaQxBCn0kP1ln4poEEmg5Q';
    const TOKEN_EMPTY = '';
    const TOKEN_UNKNOWN_USER = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1bmtub3duIiwidV9pZHgiOjAsImV4cCI6MTkzMTEwMzQ4NSwiY2xpZW50X2lkIjoiaWF4N09jQ3VZSjhTdTVwOXN3anM3Uk5vc0w3ellaNHpkVjV4eUhWeCIsInNjb3BlIjoiYWxsIn0.K5j1G3jIrEj6S0XyMXSoa3K3HOgwunjI3-ptyT0q4vE';

    const KID_TOKEN_VALID = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImtpZDEifQ.eyJzdWIiOiJyaWRpb2F1dGgydGVzdCIsInVfaWR4IjoyODAzMDUwLCJleHAiOjE5MzExMDM0ODUsImNsaWVudF9pZCI6ImlheDdPY0N1WUo4U3U1cDlzd2pzN1JOb3NMN3pZWjR6ZFY1eHlIVngiLCJzY29wZSI6ImFsbCJ9.EnmsMz06I4jpt8kAiQ4IN6O0C3p7rk7y4EY8jj1NZrVinUHzzNbW6GhQZ-gRj005JZcY7axgp4-TWPN9fKRQ9cqfTZ8KOJGc9VcaX2sLz0Oj5NJ8fRiksQAJrz8QXx6Fn4UFHKA3-2hh9_tI3dCa6JMIa6hPwOQPQevBjH8GhsY';
    const KID_TOKEN_INVALID_KID = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImtpZDAifQ.eyJzdWIiOiJyaWRpb2F1dGgydGVzdCIsInVfaWR4IjoyODAzMDUwLCJleHAiOjE5MzExMDM0ODUsImNsaWVudF9pZCI6ImlheDdPY0N1WUo4U3U1cDlzd2pzN1JOb3NMN3pZWjR6ZFY1eHlIVngiLCJzY29wZSI6ImFsbCJ9.TQ1McQRftYbL6gfZ6LY0D_Oqk70QKXz6ybiL0WMZL8XUSIctBNpHrgp59RKOPlXhlrrCGjskGF33sYywUatNIilc8j2nRtK8ehXffnc9UtXNRE9RkgBk8qqqgDtdKO2p3yRvJ04URpNiahBxl7kCfdpLp_V5PBXeKguwwKNtM0s';
    const KID_TOKEN_WITHOUT_KID = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyaWRpb2F1dGgydGVzdCIsInVfaWR4IjoyODAzMDUwLCJleHAiOjE5MzExMDM0ODUsImNsaWVudF9pZCI6ImlheDdPY0N1WUo4U3U1cDlzd2pzN1JOb3NMN3pZWjR6ZFY1eHlIVngiLCJzY29wZSI6ImFsbCJ9.hFsQDnPxk44563IfER9Nrr0hG2l_QGMZtejbLR7VRW6hhcoj7h_5CI85FLRbORCGH3lw3RZgV1p4LxDVmFT4b1s9m9Q31MmxyhpC7Wadul87M7DJzaKAroBbCdoU1QgqZN71W4ObHUFUcWp8t-h2rhL0vrf8mDdy92taX38yJvk';
}
