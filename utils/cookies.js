import { accessCookieOptions, refreshCookieOptions, githubOAuthStateCookieOptions } from '../config/cookie.js';

export const setAuthCookies = (res, accessToken, refreshToken) => {
    res.cookie('accessToken', accessToken, accessCookieOptions);
    res.cookie('refreshToken', refreshToken, refreshCookieOptions);
}

export const clearAuthCookies = (res) => {
    res.clearCookie('accessToken', accessCookieOptions);
    res.clearCookie('refreshToken', refreshCookieOptions);
}

// Holds the GitHub OAuth `state` issued at initiation so the callback can
// prove the same browser started the flow. Single-use: the callback consumes
// (clears) it before exchanging the code.
export const setGithubOAuthStateCookie = (res, state) => {
    res.cookie('github_oauth_state', state, githubOAuthStateCookieOptions);
}

export const clearGithubOAuthStateCookie = (res) => {
    res.clearCookie('github_oauth_state', githubOAuthStateCookieOptions);
}
