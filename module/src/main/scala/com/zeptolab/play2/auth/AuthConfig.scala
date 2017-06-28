package com.zeptolab.play2.auth

import play.api.Application
import play.api.cache.SyncCacheApi
import play.api.libs.crypto.CookieSigner
import play.api.mvc._

import scala.concurrent.{ExecutionContext, Future}
import scala.reflect.ClassTag

trait AuthConfig {

  type Id

  type User

  type Authority

  implicit def idTag: ClassTag[Id]

  def application: Application

  def cache: SyncCacheApi

  def signer: CookieSigner

  def sessionTimeoutInSeconds: Int

  def resolveUser(id: Id)(implicit context: ExecutionContext): Future[Option[User]]

  def loginSucceeded(request: RequestHeader)(implicit context: ExecutionContext): Future[Result]

  def logoutSucceeded(request: RequestHeader)(implicit context: ExecutionContext): Future[Result]

  def authenticationFailed(request: RequestHeader)(implicit context: ExecutionContext): Future[Result]

  def authorizationFailed(request: RequestHeader, user: User, authority: Option[Authority])(implicit context: ExecutionContext): Future[Result]

  def authorize(user: User, authority: Authority)(implicit context: ExecutionContext): Future[Boolean]

  lazy val idContainer: AsyncIdContainer[Id] = AsyncIdContainer(new CacheIdContainer[Id](cache))

  @deprecated("it will be deleted since 0.14.x. use CookieTokenAccessor constructor", since = "0.13.1")
  final lazy val cookieName: String = throw new AssertionError("use tokenAccessor setting instead.")

  @deprecated("it will be deleted since 0.14.0. use CookieTokenAccessor constructor", since = "0.13.1")
  final lazy val cookieSecureOption: Boolean = throw new AssertionError("use tokenAccessor setting instead.")

  @deprecated("it will be deleted since 0.14.0. use CookieTokenAccessor constructor", since = "0.13.1")
  final lazy val cookieHttpOnlyOption: Boolean = throw new AssertionError("use tokenAccessor setting instead.")

  @deprecated("it will be deleted since 0.14.0. use CookieTokenAccessor constructor", since = "0.13.1")
  final lazy val cookieDomainOption: Option[String] = throw new AssertionError("use tokenAccessor setting instead.")

  @deprecated("it will be deleted since 0.14.0. use CookieTokenAccessor constructor", since = "0.13.1")
  final lazy val cookiePathOption: String = throw new AssertionError("use tokenAccessor setting instead.")

  @deprecated("it will be deleted since 0.14.0. use CookieTokenAccessor constructor", since = "0.13.1")
  final lazy val isTransientCookie: Boolean = throw new AssertionError("use tokenAccessor setting instead.")

  lazy val tokenAccessor: TokenAccessor = new CookieTokenAccessor(
    cookieSigner = signer,
    cookieName = "PLAY2AUTH_SESS_ID",
    cookieSecureOption = application.mode == play.api.Mode.Prod,
    cookieHttpOnlyOption = true,
    cookieDomainOption = None,
    cookiePathOption = "/",
    cookieMaxAge = Some(sessionTimeoutInSeconds)
  )

}
