// Marketing header + footer shared by the landing page and the docs.
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../api.js";
import { Logo } from "../ui.jsx";

export function SiteHeader() {
  const { user } = useAuth();
  const [scrolled, setScrolled] = useState(false);
  const [open, setOpen] = useState(false);
  useEffect(() => {
    const f = () => setScrolled(window.scrollY > 8);
    window.addEventListener("scroll", f, { passive: true });
    f();
    return () => window.removeEventListener("scroll", f);
  }, []);
  return (
    <>
      <div className="ticker">
        New · Operator rules — govern every AI model with your own policies, enforced on every request.{" "}
        <Link to="/developers#policies">Read more →</Link>
      </div>
      <header className={`mhead${scrolled ? " scrolled" : ""}${open ? " open" : ""}`}>
        <nav className="wrap mnav" aria-label="Main">
          <Link to="/" aria-label="Virodh AI home">
            <Logo suffix=" AI" />
          </Link>
          <div className="mlinks">
            <a href="/#platform">Platform</a>
            <Link to="/developers">Developers</Link>
            <a href="/#research">Research</a>
            <a href="/#security">Security</a>
          </div>
          <div className="mright">
            {user ? (
              <Link className="btn btn-dark btn-sm" to="/app">
                Open dashboard
              </Link>
            ) : (
              <>
                <Link className="btn btn-ghost btn-sm" to="/signin">
                  Log in
                </Link>
                <Link className="btn btn-dark btn-sm" to="/signup">
                  Sign up
                </Link>
              </>
            )}
          </div>
          <button
            className="btn btn-light btn-sm mmenu"
            type="button"
            aria-expanded={open}
            onClick={() => setOpen(!open)}
          >
            Menu
          </button>
        </nav>
      </header>
    </>
  );
}

export function SiteFooter() {
  return (
    <footer className="mfoot">
      <div className="wrap">
        <div className="fgrid">
          <div>
            <Logo suffix=" AI" />
            <p className="muted" style={{ maxWidth: 300, fontSize: 15 }}>
              The governance layer for AI models. Your rules, enforced on every request, for every model.
            </p>
          </div>
          <div>
            <h3>Platform</h3>
            <ul>
              <li>
                <a href="/#platform">Gateway</a>
              </li>
              <li>
                <Link to="/developers#scan">Scan API</Link>
              </li>
              <li>
                <Link to="/developers#policies">Policies</Link>
              </li>
              <li>
                <Link to="/app">Dashboard</Link>
              </li>
            </ul>
          </div>
          <div>
            <h3>Developers</h3>
            <ul>
              <li>
                <Link to="/developers#quickstart">Quickstart</Link>
              </li>
              <li>
                <a href="/docs">API reference</a>
              </li>
              <li>
                <Link to="/developers#deploy">Deployment</Link>
              </li>
              <li>
                <Link to="/developers#errors">Errors</Link>
              </li>
            </ul>
          </div>
          <div>
            <h3>Research</h3>
            <ul>
              <li>
                <Link to="/app/test-lab">Test lab</Link>
              </li>
              <li>
                <Link to="/app/evaluation">Evaluation</Link>
              </li>
              <li>
                <Link to="/developers#limitations">Limitations</Link>
              </li>
            </ul>
          </div>
          <div>
            <h3>Project</h3>
            <ul>
              <li>
                <Link to="/developers#attribution">Attribution</Link>
              </li>
              <li>
                <Link to="/developers#security">Security design</Link>
              </li>
            </ul>
          </div>
        </div>
        <div className="flegal">
          <span>© 2026 Virodh AI · hackathon prototype, TIET Saturnalia</span>
          <span>Not affiliated with any model provider · model names belong to their owners</span>
        </div>
      </div>
    </footer>
  );
}
