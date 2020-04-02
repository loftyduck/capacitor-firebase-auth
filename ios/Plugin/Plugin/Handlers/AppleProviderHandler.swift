import Foundation
import CryptoKit
import Capacitor
import FirebaseCore
import FirebaseAuth
import AuthenticationServices

fileprivate var currentNonce: String?

class AppleProviderHandler: NSObject, ProviderHandler {

    var plugin: CapacitorFirebaseAuth? = nil

    func initialize(plugin: CapacitorFirebaseAuth) {
        print("Initializing Apple Provider Handler")

        self.plugin = plugin

        if #available(iOS 13.0, *) {} else {
            self.plugin?.handleError(message: "Sign in with Apple is available on iOS 13.0+ only.")
        }
    }

    @available(iOS 13, *)
    func signIn(call: CAPPluginCall) {
        let nonce = randomNonceString()
        currentNonce = nonce
        
        let appleIDProvider = ASAuthorizationAppleIDProvider()
        let request = appleIDProvider.createRequest()
        request.requestedScopes = [.fullName, .email]
        request.nonce = sha256(nonce)

        let authorizationController = ASAuthorizationController(authorizationRequests: [request])
        authorizationController.delegate = self
        authorizationController.presentationContextProvider = self
        
        authorizationController.performRequests()
    }

    func isAuthenticated() -> Bool {
        let appleIDProvider = ASAuthorizationAppleIDProvider()
        let user = Auth.auth().currentUser
        print("isAuthenticated")
        print(user?.providerData[0].uid)
        appleIDProvider.getCredentialState(forUserID: user?.providerData[0].uid) { (credentialState, error) in
            switch credentialState {
            case .authorized:
                return true // The Apple ID credential is valid.
            case .revoked, .notFound:
                return false
            }
        }
    }

    func fillResult(data: PluginResultData) -> PluginResultData {
        
    }

    func signOut(){
        // Apple doesn't have any sign out function, the best we can do is check credential state as isAuthenticated does
    }
    
    @available(iOS 13, *)
    private func sha256(_ input: String) -> String {
      let inputData = Data(input.utf8)
      let hashedData = SHA256.hash(data: inputData)
      let hashString = hashedData.compactMap {
        return String(format: "%02x", $0)
      }.joined()

      return hashString
    }
    
    private func randomNonceString(length: Int = 32) -> String {
      precondition(length > 0)
      let charset: Array<Character> =
          Array("0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz-._")
      var result = ""
      var remainingLength = length

      while remainingLength > 0 {
        let randoms: [UInt8] = (0 ..< 16).map { _ in
          var random: UInt8 = 0
          let errorCode = SecRandomCopyBytes(kSecRandomDefault, 1, &random)
          if errorCode != errSecSuccess {
            fatalError("Unable to generate nonce. SecRandomCopyBytes failed with OSStatus \(errorCode)")
          }
          return random
        }

        randoms.forEach { random in
          if remainingLength == 0 {
            return
          }

          if random < charset.count {
            result.append(charset[Int(random)])
            remainingLength -= 1
          }
        }
      }

      return result
    }
}

@available(iOS 13.0, *)
extension AppleProviderHandler: ASAuthorizationControllerDelegate {

    public func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        
        guard let nonce = currentNonce else {
          fatalError("Invalid state: A login callback was received, but no login request was sent.")
        }
        
        guard let appleIDCredential = authorization.credential as? ASAuthorizationAppleIDCredential else {
            self.plugin?.handleError(message: "Unable to find credential")
            return
        }

        guard let appleIDToken = appleIDCredential.identityToken else {
          self.plugin?.handleError(message: "Unable to find identity token")
          return
        }

        guard let idTokenString = String(data: appleIDToken, encoding: .utf8) else {
          self.plugin?.handleError(message: "Unable to serialize token string from data: \(appleIDToken.debugDescription)")
          return
        }
        
        guard let userId = authorization.user else {
          self.plugin?.handleError(message: "Unable to find userId")
          return
        }
        
        print("authController")
        print(userId)

        let credential = OAuthProvider.credential(withProviderID: "apple.com", IDToken: idTokenString, rawNonce: nonce)
        self.plugin?.handleAuthCredentials(credential: credential);
    }

    public func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        self.signOut()
    }
}
