require 'omniauth-oauth2'
require 'builder'
require 'nokogiri'
require 'rest_client'

module OmniAuth
  module Strategies
    class MrcTrain < OmniAuth::Strategies::OAuth2
      option :name, 'mrc_train'

      option :client_options, { login_page_url: 'MUST BE PROVIDED' }

      uid { info[:uid] }

      info { raw_user_info }

      def request_phase
        slug = session['omniauth.params']['origin'].gsub(/\//,"")
        redirect login_page_url + "?redirectURL=" + callback_url + "?slug=#{slug}"
      end

      def callback_phase
        slug = request.params['slug']
        account = Account.find_by(slug: slug)
        app_event = account.app_events.where(id: options.app_options.app_event_id).first_or_create(activity_type: 'sso')

        self.env['omniauth.auth'] = auth_hash
        self.env['omniauth.origin'] = '/' + slug
        self.env['omniauth.app_event_id'] = app_event.id
        call_app!
      end

      def auth_hash
        hash = AuthHash.new(:provider => name, :uid => uid)
        hash.info = info
        hash
      end

      def raw_user_info
        {
          external_user_id: request.params['UserID'],
          first_name: request.params['Name'].try(:split, ',').try(:last),
          last_name: request.params['Name'].try(:split, ',').try(:first),
          email: request.params['email'],
          uid: request.params['UserID'],
          sellable_id: request.params['ProviderCourseID'],
          external_product_id: request.params['TrainCourseID']
        }
      end

      private

      def login_page_url
        options.client_options.login_page_url
      end

    end
  end
end
