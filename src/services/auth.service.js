const httpStatus = require('http-status');
const ethers = require('ethers');
const crypto = require('crypto');
const config = require('../config/config');
const tokenService = require('./token.service');
const userService = require('./user.service');
const Token = require('../models/token.model');
const ApiError = require('../utils/ApiError');
const { tokenTypes } = require('../config/tokens');
const logger = require('../config/logger');

/**
 * Login with username and password
 * @param {string} email
 * @param {string} password
 * @returns {Promise<User>}
 */
const loginUserWithEmailAndPassword = async (email, password) => {
  const user = await userService.getUserByEmail(email);
  if (!user || !(await user.isPasswordMatch(password))) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Incorrect email or password');
  }
  return user;
};

/**
 * Logout
 * @param {string} refreshToken
 * @returns {Promise}
 */
const logout = async (refreshToken) => {
  const refreshTokenDoc = await Token.findOne({ token: refreshToken, type: tokenTypes.REFRESH, blacklisted: false });
  if (!refreshTokenDoc) {
    throw new ApiError(httpStatus.NOT_FOUND, 'Not found');
  }
  await refreshTokenDoc.remove();
};

/**
 * Refresh auth tokens
 * @param {string} refreshToken
 * @returns {Promise<Object>}
 */
const refreshAuth = async (refreshToken) => {
  try {
    const refreshTokenDoc = await tokenService.verifyToken(refreshToken, tokenTypes.REFRESH);
    const user = await userService.getUserById(refreshTokenDoc.user);
    if (!user) {
      throw new Error();
    }
    await refreshTokenDoc.remove();
    return tokenService.generateAuthTokens(user);
  } catch (error) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Please authenticate');
  }
};

/**
 * Reset password
 * @param {string} resetPasswordToken
 * @param {string} newPassword
 * @returns {Promise}
 */
const resetPassword = async (resetPasswordToken, newPassword) => {
  try {
    const resetPasswordTokenDoc = await tokenService.verifyToken(resetPasswordToken, tokenTypes.RESET_PASSWORD);
    const user = await userService.getUserById(resetPasswordTokenDoc.user);
    if (!user) {
      throw new Error();
    }
    await userService.updateUserById(user.id, { password: newPassword });
    await Token.deleteMany({ user: user.id, type: tokenTypes.RESET_PASSWORD });
  } catch (error) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Password reset failed');
  }
};

/**
 * Verify email
 * @param {string} verifyEmailToken
 * @returns {Promise}
 */
const verifyEmail = async (verifyEmailToken) => {
  try {
    const verifyEmailTokenDoc = await tokenService.verifyToken(verifyEmailToken, tokenTypes.VERIFY_EMAIL);
    const user = await userService.getUserById(verifyEmailTokenDoc.user);
    if (!user) {
      throw new Error();
    }
    await Token.deleteMany({ user: user.id, type: tokenTypes.VERIFY_EMAIL });
    await userService.updateUserById(user.id, { isEmailVerified: true });
  } catch (error) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Email verification failed');
  }
};

/**
 * Login with address
 * @param {string} address
 * @returns {Promise<User>}
 */
const createUserWithAddress = async (address) => {
  let user = await userService.getUserByAddress(address);
  if (!user) {
    user = await userService.createUser({
      _id: address.toLowerCase(),
      username: address,
      name: address,
      address,
      email: `${address}@mail.freecity.finance`,
      password: crypto.randomBytes(20).toString('hex'),
    });
  }
  if (user) {
    // random new nonce for next authentication
    await user.genNonce();
    logger.debug('saved new nonce', user.nonce);
  }
  return user;
};

/**
 * Login with address and signature
 * @param {string} address
 * @returns {Promise<User>}
 */
const loginUserWithAddressAndSignature = async (address, signature) => {
  const user = await userService.getUserByAddress(address);
  if (!user) {
    throw new ApiError(httpStatus.NOT_FOUND, 'Not found address, pls register with address before login');
  }
  const msg = `${config.constance.verifyTemplate}: ${user.nonce}`;
  logger.debug(`verify message %o`, msg);
  const signerAddress = ethers.utils.verifyMessage(msg, signature);
  logger.debug(`signerAddress %o`, signerAddress);
  if (signerAddress.toLowerCase() === address.toLowerCase()) {
    // change nonce for next login
    await user.genNonce();
    logger.debug('--- Auth success > %o', user);
    return user;
  }
  throw new ApiError(httpStatus.UNAUTHORIZED, 'Incorrect public address and nonce');
};

module.exports = {
  loginUserWithEmailAndPassword,
  logout,
  refreshAuth,
  resetPassword,
  verifyEmail,
  createUserWithAddress,
  loginUserWithAddressAndSignature,
};
