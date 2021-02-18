# frozen_string_literal: true

module JWTSessions
  class AccessToken
    attr_reader :payload, :uid, :expiration, :csrf, :store, :namespace

    def initialize(csrf, payload, store, namespace, uid = SecureRandom.uuid, expiration = JWTSessions.access_expiration)
      @csrf       = csrf
      @uid        = uid
      @expiration = expiration
      @payload    = payload.merge("uid" => uid, "exp" => expiration.to_i)
      @store      = store
      @namespace  = namespace
    end

    def destroy
      store.destroy_access(uid, namespace)
    end

    def refresh_uid=(uid)
      self.payload["ruid"] = uid
    end

    def refresh_uid
      payload["ruid"]
    end

    def token
      Token.encode(payload)
    end

    class << self
      def create(csrf, payload, store, namespace, expiration = JWTSessions.access_expiration)
        new(csrf, payload, store, namespace, SecureRandom.uuid, expiration).tap do |inst|
          store.persist_access(inst.uid, inst.csrf, inst.expiration, inst.namespace)
        end
      end

      def destroy(uid, store, namespace)
        store.destroy_access(uid, namespace)
      end

      # AccessToken's find method cannot be used to retrieve token's payload
      # or any other information but is intended to identify if the token is present
      # and to retrieve session's CSRF token
      def find(uid, store, namespace)
        token_attrs = store.fetch_access(uid, namespace)
        raise Errors::Unauthorized, "Access token not found" if token_attrs.empty?
        build_with_token_attrs(store, namespace, uid, token_attrs)
      end

      private

      def build_with_token_attrs(store, namespace, uid, token_attrs)
        new(token_attrs[:csrf], {}, store, namespace, uid)
      end
    end
  end
end
