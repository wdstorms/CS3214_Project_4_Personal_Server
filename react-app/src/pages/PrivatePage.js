import React from 'react';
import { useSelector } from 'react-redux';
import { Container } from 'reactstrap';
import RequireAuthentication from '../containers/RequireAuthentication';

const PrivatePage = () => {
  let user = useSelector(state => state.auth);

  return (<Container>
    <h1>Welcome to a private page</h1>
    <div>
      You have successfully authenticated as user <tt>{user.sub}</tt>.
      Your token was issued at {new Date(user.iat*1000).toString()}, 
      it expires {new Date(user.exp*1000).toString()}
    </div>
    <div>
      This page is "private" only inasmuch as the front-end does not
      display it to unauthenticated users.  In a fully-fledged app,
      this page would now perform API requests that require authentication.
    </div>
  </Container>);
}

export default RequireAuthentication(PrivatePage);
