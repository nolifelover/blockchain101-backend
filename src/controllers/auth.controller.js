const httpStatus = require('http-status');
const catchAsync = require('../utils/catchAsync');
const ApiError = require('../utils/ApiError');
const { authService, userService, tokenService, emailService } = require('../services');
const logger = require('../config/logger');
const config = require('../config/config');

const register = catchAsync(async (req, res) => {
  const user = await userService.createUser(req.body);
  const tokens = await tokenService.generateAuthTokens(user);
  res.status(httpStatus.CREATED).send({ user, tokens });
});

const login = catchAsync(async (req, res) => {
  const { email, password } = req.body;
  const user = await authService.loginUserWithEmailAndPassword(email, password);
  const tokens = await tokenService.generateAuthTokens(user);
  res.send({ user, tokens });
});

const logout = catchAsync(async (req, res) => {
  await authService.logout(req.body.refreshToken);
  res.status(httpStatus.NO_CONTENT).send();
});

const refreshTokens = catchAsync(async (req, res) => {
  const tokens = await authService.refreshAuth(req.body.refreshToken);
  res.send({ ...tokens });
});

const forgotPassword = catchAsync(async (req, res) => {
  const resetPasswordToken = await tokenService.generateResetPasswordToken(req.body.email);
  await emailService.sendResetPasswordEmail(req.body.email, resetPasswordToken);
  res.status(httpStatus.NO_CONTENT).send();
});

const resetPassword = catchAsync(async (req, res) => {
  await authService.resetPassword(req.query.token, req.body.password);
  res.status(httpStatus.NO_CONTENT).send();
});

const sendVerificationEmail = catchAsync(async (req, res) => {
  const verifyEmailToken = await tokenService.generateVerifyEmailToken(req.user);
  await emailService.sendVerificationEmail(req.user.email, verifyEmailToken);
  res.status(httpStatus.NO_CONTENT).send();
});

const verifyEmail = catchAsync(async (req, res) => {
  await authService.verifyEmail(req.query.token);
  res.status(httpStatus.NO_CONTENT).send();
});

const signatureRegister = catchAsync(async (req, res) => {
  if (!req.body.name) {
    req.body.name = req.body.publicAddress;
  }
  req.body.email = `${req.body.publicAddress}@email.${config.constance.domain}`;
  req.body.isEmailVerified = false;
  const user = await userService.createUser(req.body);
  res.status(httpStatus.CREATED).send(user);
});

const registerWithAddress = catchAsync(async (req, res) => {
  const { address } = req.body;
  logger.debug('body %o=%o', req.body.address, address);
  const user = await authService.createUserWithAddress(address);
  if (!user || (user && !user.nonce)) {
    throw new ApiError(httpStatus.NOT_FOUND, 'Not found or Error on create user with address');
  }

  const result = {
    nonce: user.nonce,
    msg: `${config.constance.verifyTemplate}: ${user.nonce}`,
  };

  res.json(result);
});

const loginWithSignature = catchAsync(async (req, res) => {
  logger.debug('-- authentication');
  const { address, signature } = req.body;
  const user = await authService.loginUserWithAddressAndSignature(address, signature);
  const tokens = await tokenService.generateAuthTokens(user);
  res.status(httpStatus.CREATED).send({ user, tokens });
});

module.exports = {
  register,
  login,
  logout,
  refreshTokens,
  forgotPassword,
  resetPassword,
  sendVerificationEmail,
  verifyEmail,
  signatureRegister,
  registerWithAddress,
  loginWithSignature,
};
