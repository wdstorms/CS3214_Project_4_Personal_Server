import React from 'react';
import { connect } from 'react-redux';
import TopNavBar from '../components/TopNavBar';
import Logout from '../components/Logout';
import LoginPage from '../pages/LoginPage';
import PublicPage from '../pages/PublicPage';
import NotFoundPage from '../pages/NotFoundPage';
import HomePage from '../pages/HomePage';
import PrivatePage from '../pages/PrivatePage';
import PlayerPage from '../pages/PlayerPage';

import { Routes, Route } from 'react-router-dom';

import config from '../config';

/** AppContainer renders the navigation bar on top and its
 * children in the main part of the page.  Its children will
 * be chosen based on the selected route.
 */
const AppContainer = (props) => (
    <div>
      <TopNavBar branding={config.branding}
                  menus={config.menus} 
                  user={props.user} 
                  loginUrl={`/login`}
                  logoutUrl={`/logout`}
        />
      <div className="container-fluid marketing">
          <Routes>
              <Route exact path={`/`} element={<HomePage />} />
              <Route path={`/logout`} element={<Logout />} />
              <Route path={`/login`} element={<LoginPage />} />
              <Route path={`/public`} element={<PublicPage />} />
              <Route path={`/protected`} element={<PrivatePage />} />
              <Route path={`/player`} element={<PlayerPage />} />
              <Route element={<NotFoundPage />} />
          </Routes>
      </div>
    </div>
);

function mapStateToProps(state) {
  return {
    user: state.auth
  };
}

function mapDispatchToProps(dispatch) {
  return {
    dispatch
  };
}

export default connect(mapStateToProps, mapDispatchToProps)(AppContainer);
