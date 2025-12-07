"""Known breaking changes database for popular packages.

This provides curated, accurate breaking change information for major
popular packages where changelog parsing may be unreliable.

Sources:
- Official migration guides
- GitHub release notes
- Package documentation
"""

from dataclasses import dataclass

from blastauri.core.models import BreakingChange, BreakingChangeType, Ecosystem


@dataclass
class KnownBreakingChange:
    """A known breaking change with version range."""

    ecosystem: Ecosystem
    package: str
    from_version: str  # Versions < this are affected
    to_version: str  # Version where change was introduced
    change: BreakingChange


# Curated database of known breaking changes for popular packages
KNOWN_BREAKING_CHANGES: list[KnownBreakingChange] = [
    # ==================== NPM ====================

    # lodash 4.x -> 5.x
    KnownBreakingChange(
        ecosystem=Ecosystem.NPM,
        package="lodash",
        from_version="5.0.0",
        to_version="5.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.REMOVED_FUNCTION,
            description="_.pluck removed, use _.map with iteratee shorthand",
            old_api="_.pluck(collection, 'property')",
            new_api="_.map(collection, 'property')",
            migration_guide="Replace _.pluck(collection, 'prop') with _.map(collection, 'prop')",
            source="known_breaking_changes",
        ),
    ),
    KnownBreakingChange(
        ecosystem=Ecosystem.NPM,
        package="lodash",
        from_version="5.0.0",
        to_version="5.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.REMOVED_FUNCTION,
            description="_.where removed, use _.filter with matches shorthand",
            old_api="_.where(collection, {key: value})",
            new_api="_.filter(collection, {key: value})",
            migration_guide="Replace _.where with _.filter",
            source="known_breaking_changes",
        ),
    ),
    KnownBreakingChange(
        ecosystem=Ecosystem.NPM,
        package="lodash",
        from_version="5.0.0",
        to_version="5.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_BEHAVIOR,
            description="_.merge now handles arrays differently, concatenating instead of merging by index",
            old_api="_.merge({a: [1,2]}, {a: [3]})",
            new_api="_.merge({a: [1,2]}, {a: [3]})",
            migration_guide="Arrays are now concatenated; use _.mergeWith for custom behavior",
            source="known_breaking_changes",
        ),
    ),

    # Express 4.x -> 5.x
    KnownBreakingChange(
        ecosystem=Ecosystem.NPM,
        package="express",
        from_version="5.0.0",
        to_version="5.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.REMOVED_FUNCTION,
            description="app.del() removed, use app.delete()",
            old_api="app.del('/path', handler)",
            new_api="app.delete('/path', handler)",
            migration_guide="Replace app.del() with app.delete()",
            source="known_breaking_changes",
        ),
    ),
    KnownBreakingChange(
        ecosystem=Ecosystem.NPM,
        package="express",
        from_version="5.0.0",
        to_version="5.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_BEHAVIOR,
            description="Promise rejection in route handlers now caught automatically",
            old_api="Unhandled rejections crash server",
            new_api="Rejections passed to error handler",
            migration_guide="Remove manual try/catch wrappers if using async handlers",
            source="known_breaking_changes",
        ),
    ),
    KnownBreakingChange(
        ecosystem=Ecosystem.NPM,
        package="express",
        from_version="5.0.0",
        to_version="5.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_SIGNATURE,
            description="req.host now returns hostname only, not hostname:port",
            old_api="req.host returns 'example.com:3000'",
            new_api="req.host returns 'example.com'",
            migration_guide="Use req.hostname for just hostname, reconstruct with req.get('host') if port needed",
            source="known_breaking_changes",
        ),
    ),

    # React 17 -> 18
    KnownBreakingChange(
        ecosystem=Ecosystem.NPM,
        package="react",
        from_version="18.0.0",
        to_version="18.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_SIGNATURE,
            description="ReactDOM.render deprecated, use createRoot",
            old_api="ReactDOM.render(<App />, container)",
            new_api="createRoot(container).render(<App />)",
            migration_guide="Import createRoot from 'react-dom/client' and use new API",
            source="known_breaking_changes",
        ),
    ),
    KnownBreakingChange(
        ecosystem=Ecosystem.NPM,
        package="react",
        from_version="18.0.0",
        to_version="18.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_BEHAVIOR,
            description="Automatic batching for all state updates, not just React event handlers",
            old_api="State updates in setTimeout not batched",
            new_api="All state updates batched by default",
            migration_guide="Use flushSync() if you need synchronous updates",
            source="known_breaking_changes",
        ),
    ),
    KnownBreakingChange(
        ecosystem=Ecosystem.NPM,
        package="react-dom",
        from_version="18.0.0",
        to_version="18.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_SIGNATURE,
            description="ReactDOM.render deprecated, use createRoot",
            old_api="ReactDOM.render(<App />, container)",
            new_api="createRoot(container).render(<App />)",
            migration_guide="Import createRoot from 'react-dom/client' and use new API",
            source="known_breaking_changes",
        ),
    ),

    # axios 0.x -> 1.x
    KnownBreakingChange(
        ecosystem=Ecosystem.NPM,
        package="axios",
        from_version="1.0.0",
        to_version="1.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_BEHAVIOR,
            description="Automatic JSON transformation now uses native JSON.parse",
            old_api="Custom reviver in transformResponse",
            new_api="Native JSON.parse behavior",
            migration_guide="Use custom transformResponse if you relied on previous behavior",
            source="known_breaking_changes",
        ),
    ),
    KnownBreakingChange(
        ecosystem=Ecosystem.NPM,
        package="axios",
        from_version="1.0.0",
        to_version="1.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_SIGNATURE,
            description="AxiosError now extends Error, error.toJSON() signature changed",
            old_api="error.toJSON() returns full config",
            new_api="error.toJSON() returns sanitized config",
            migration_guide="Access error.config directly for full configuration",
            source="known_breaking_changes",
        ),
    ),

    # Next.js 12 -> 13
    KnownBreakingChange(
        ecosystem=Ecosystem.NPM,
        package="next",
        from_version="13.0.0",
        to_version="13.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_BEHAVIOR,
            description="App Router introduced with new file-based routing in app/ directory",
            old_api="pages/ directory routing",
            new_api="app/ directory with layout.js, page.js conventions",
            migration_guide="Migrate pages incrementally; pages/ still works alongside app/",
            source="known_breaking_changes",
        ),
    ),
    KnownBreakingChange(
        ecosystem=Ecosystem.NPM,
        package="next",
        from_version="13.0.0",
        to_version="13.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.REMOVED_FUNCTION,
            description="next/head deprecated in app/ directory, use Metadata API",
            old_api="import Head from 'next/head'",
            new_api="export const metadata = { title: '...' }",
            migration_guide="Use generateMetadata or metadata export in app/ directory",
            source="known_breaking_changes",
        ),
    ),

    # TypeScript 4.x -> 5.x
    KnownBreakingChange(
        ecosystem=Ecosystem.NPM,
        package="typescript",
        from_version="5.0.0",
        to_version="5.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_BEHAVIOR,
            description="Enums now have more strict type checking",
            old_api="Loose enum comparisons allowed",
            new_api="Strict enum type checking",
            migration_guide="Review enum usage and add explicit type annotations",
            source="known_breaking_changes",
        ),
    ),
    KnownBreakingChange(
        ecosystem=Ecosystem.NPM,
        package="typescript",
        from_version="5.0.0",
        to_version="5.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_DEFAULT,
            description="moduleResolution: bundler is now a valid option and recommended for bundlers",
            old_api="moduleResolution: node",
            new_api="moduleResolution: bundler",
            migration_guide="Consider using 'bundler' resolution for projects using bundlers",
            source="known_breaking_changes",
        ),
    ),

    # ==================== Python ====================

    # Django 3.x -> 4.x
    KnownBreakingChange(
        ecosystem=Ecosystem.PYPI,
        package="django",
        from_version="4.0",
        to_version="4.0",
        change=BreakingChange(
            change_type=BreakingChangeType.REMOVED_FUNCTION,
            description="USE_L10N setting removed, localization always enabled",
            old_api="USE_L10N = True in settings",
            new_api="Localization enabled by default",
            migration_guide="Remove USE_L10N from settings.py",
            source="known_breaking_changes",
        ),
    ),
    KnownBreakingChange(
        ecosystem=Ecosystem.PYPI,
        package="django",
        from_version="4.0",
        to_version="4.0",
        change=BreakingChange(
            change_type=BreakingChangeType.REMOVED_FUNCTION,
            description="url() function removed, use path() or re_path()",
            old_api="from django.conf.urls import url",
            new_api="from django.urls import path, re_path",
            migration_guide="Replace url() with path() or re_path()",
            source="known_breaking_changes",
        ),
    ),
    KnownBreakingChange(
        ecosystem=Ecosystem.PYPI,
        package="django",
        from_version="4.0",
        to_version="4.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_BEHAVIOR,
            description="CSRF_TRUSTED_ORIGINS now requires scheme (https://)",
            old_api="CSRF_TRUSTED_ORIGINS = ['example.com']",
            new_api="CSRF_TRUSTED_ORIGINS = ['https://example.com']",
            migration_guide="Add https:// prefix to all CSRF_TRUSTED_ORIGINS entries",
            source="known_breaking_changes",
        ),
    ),

    # Flask 2.x -> 3.x
    KnownBreakingChange(
        ecosystem=Ecosystem.PYPI,
        package="flask",
        from_version="3.0.0",
        to_version="3.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.REMOVED_FUNCTION,
            description="Removed deprecated helpers module",
            old_api="from flask import helpers",
            new_api="Direct imports from flask",
            migration_guide="Import directly from flask package",
            source="known_breaking_changes",
        ),
    ),
    KnownBreakingChange(
        ecosystem=Ecosystem.PYPI,
        package="flask",
        from_version="3.0.0",
        to_version="3.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_SIGNATURE,
            description="app.run() no longer defaults to threaded=True on Windows",
            old_api="app.run() with threaded=True default",
            new_api="app.run() with threaded=False default",
            migration_guide="Explicitly pass threaded=True if needed",
            source="known_breaking_changes",
        ),
    ),

    # Pydantic 1.x -> 2.x
    KnownBreakingChange(
        ecosystem=Ecosystem.PYPI,
        package="pydantic",
        from_version="2.0.0",
        to_version="2.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_SIGNATURE,
            description="Model.dict() renamed to Model.model_dump()",
            old_api="model.dict()",
            new_api="model.model_dump()",
            migration_guide="Replace .dict() with .model_dump()",
            source="known_breaking_changes",
        ),
    ),
    KnownBreakingChange(
        ecosystem=Ecosystem.PYPI,
        package="pydantic",
        from_version="2.0.0",
        to_version="2.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_SIGNATURE,
            description="Model.json() renamed to Model.model_dump_json()",
            old_api="model.json()",
            new_api="model.model_dump_json()",
            migration_guide="Replace .json() with .model_dump_json()",
            source="known_breaking_changes",
        ),
    ),
    KnownBreakingChange(
        ecosystem=Ecosystem.PYPI,
        package="pydantic",
        from_version="2.0.0",
        to_version="2.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_SIGNATURE,
            description="Model.parse_obj() renamed to Model.model_validate()",
            old_api="Model.parse_obj(data)",
            new_api="Model.model_validate(data)",
            migration_guide="Replace parse_obj with model_validate",
            source="known_breaking_changes",
        ),
    ),
    KnownBreakingChange(
        ecosystem=Ecosystem.PYPI,
        package="pydantic",
        from_version="2.0.0",
        to_version="2.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_SIGNATURE,
            description="@validator decorator replaced with @field_validator",
            old_api="@validator('field_name')",
            new_api="@field_validator('field_name')",
            migration_guide="Use @field_validator with mode='before' or mode='after'",
            source="known_breaking_changes",
        ),
    ),
    KnownBreakingChange(
        ecosystem=Ecosystem.PYPI,
        package="pydantic",
        from_version="2.0.0",
        to_version="2.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_SIGNATURE,
            description="Config inner class replaced with model_config",
            old_api="class Config: extra = 'forbid'",
            new_api="model_config = ConfigDict(extra='forbid')",
            migration_guide="Use model_config = ConfigDict(...) instead of Config class",
            source="known_breaking_changes",
        ),
    ),

    # requests 2.x (major changes)
    KnownBreakingChange(
        ecosystem=Ecosystem.PYPI,
        package="requests",
        from_version="2.28.0",
        to_version="2.28.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_BEHAVIOR,
            description="urllib3 2.0 dependency with stricter SSL validation",
            old_api="Lenient SSL certificate validation",
            new_api="Strict SSL certificate validation",
            migration_guide="Ensure valid SSL certificates or use verify=False (not recommended)",
            source="known_breaking_changes",
        ),
    ),

    # SQLAlchemy 1.x -> 2.x
    KnownBreakingChange(
        ecosystem=Ecosystem.PYPI,
        package="sqlalchemy",
        from_version="2.0.0",
        to_version="2.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_SIGNATURE,
            description="Query.get() replaced with Session.get()",
            old_api="session.query(Model).get(id)",
            new_api="session.get(Model, id)",
            migration_guide="Use session.get(Model, primary_key) instead of query().get()",
            source="known_breaking_changes",
        ),
    ),
    KnownBreakingChange(
        ecosystem=Ecosystem.PYPI,
        package="sqlalchemy",
        from_version="2.0.0",
        to_version="2.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_BEHAVIOR,
            description="2.0 style queries with select() required by default",
            old_api="session.query(Model).filter(...)",
            new_api="session.execute(select(Model).where(...))",
            migration_guide="Use select() statements with session.execute() or session.scalars()",
            source="known_breaking_changes",
        ),
    ),

    # pytest 7.x -> 8.x
    KnownBreakingChange(
        ecosystem=Ecosystem.PYPI,
        package="pytest",
        from_version="8.0.0",
        to_version="8.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.REMOVED_FUNCTION,
            description="py.path.local deprecated, use pathlib.Path",
            old_api="tmp_path returns py.path.local",
            new_api="tmp_path returns pathlib.Path",
            migration_guide="Update code to use pathlib.Path methods",
            source="known_breaking_changes",
        ),
    ),

    # ==================== More NPM Packages ====================

    # webpack 4.x -> 5.x
    KnownBreakingChange(
        ecosystem=Ecosystem.NPM,
        package="webpack",
        from_version="5.0.0",
        to_version="5.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.REMOVED_FUNCTION,
            description="Node.js polyfills no longer included by default",
            old_api="Automatic polyfills for crypto, buffer, etc.",
            new_api="Must manually add polyfills or use fallback: false",
            migration_guide="Add resolve.fallback config for Node.js core modules",
            source="known_breaking_changes",
        ),
    ),
    KnownBreakingChange(
        ecosystem=Ecosystem.NPM,
        package="webpack",
        from_version="5.0.0",
        to_version="5.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_BEHAVIOR,
            description="Asset modules replace file-loader, url-loader, raw-loader",
            old_api="Use file-loader for assets",
            new_api="Use asset/resource, asset/inline, asset/source",
            migration_guide="Replace loaders with asset module types in webpack config",
            source="known_breaking_changes",
        ),
    ),

    # moment -> dayjs migration (moment deprecated)
    KnownBreakingChange(
        ecosystem=Ecosystem.NPM,
        package="moment",
        from_version="2.30.0",
        to_version="2.30.0",
        change=BreakingChange(
            change_type=BreakingChangeType.DEPRECATED,
            description="Moment.js is in maintenance mode, consider alternatives",
            old_api="moment()",
            new_api="dayjs() or date-fns",
            migration_guide="Consider migrating to dayjs (drop-in replacement) or date-fns",
            source="known_breaking_changes",
        ),
    ),

    # jest 28 -> 29
    KnownBreakingChange(
        ecosystem=Ecosystem.NPM,
        package="jest",
        from_version="29.0.0",
        to_version="29.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_BEHAVIOR,
            description="Default snapshot format changed to prettier v3",
            old_api="Snapshots formatted with prettier v2",
            new_api="Snapshots formatted with prettier v3",
            migration_guide="Update snapshots with jest -u after upgrading",
            source="known_breaking_changes",
        ),
    ),
    KnownBreakingChange(
        ecosystem=Ecosystem.NPM,
        package="jest",
        from_version="29.0.0",
        to_version="29.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_DEFAULT,
            description="Node 14 support dropped, minimum is Node 16",
            old_api="Node 14 supported",
            new_api="Node 16+ required",
            migration_guide="Upgrade Node.js to version 16 or higher",
            source="known_breaking_changes",
        ),
    ),

    # eslint 8 -> 9
    KnownBreakingChange(
        ecosystem=Ecosystem.NPM,
        package="eslint",
        from_version="9.0.0",
        to_version="9.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_BEHAVIOR,
            description="Flat config (eslint.config.js) is now default",
            old_api=".eslintrc.* configuration files",
            new_api="eslint.config.js flat config",
            migration_guide="Migrate to flat config or use ESLINT_USE_FLAT_CONFIG=false",
            source="known_breaking_changes",
        ),
    ),
    KnownBreakingChange(
        ecosystem=Ecosystem.NPM,
        package="eslint",
        from_version="9.0.0",
        to_version="9.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.REMOVED_FUNCTION,
            description="Many formatters removed from core, now separate packages",
            old_api="--format stylish (built-in)",
            new_api="Install eslint-formatter-stylish separately",
            migration_guide="Install required formatters as separate packages",
            source="known_breaking_changes",
        ),
    ),

    # ==================== More Python Packages ====================

    # celery 4.x -> 5.x
    KnownBreakingChange(
        ecosystem=Ecosystem.PYPI,
        package="celery",
        from_version="5.0.0",
        to_version="5.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.REMOVED_FUNCTION,
            description="Python 2 support removed, async keyword conflicts resolved",
            old_api="Python 2.7 compatible",
            new_api="Python 3.6+ only",
            migration_guide="Ensure Python 3.6+ and update async-related code",
            source="known_breaking_changes",
        ),
    ),
    KnownBreakingChange(
        ecosystem=Ecosystem.PYPI,
        package="celery",
        from_version="5.0.0",
        to_version="5.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_SIGNATURE,
            description="Task.request now uses contextvars instead of thread-locals",
            old_api="Thread-local task.request",
            new_api="Contextvar-based task.request",
            migration_guide="Update code relying on thread-local task.request behavior",
            source="known_breaking_changes",
        ),
    ),

    # boto3 / botocore major updates
    KnownBreakingChange(
        ecosystem=Ecosystem.PYPI,
        package="boto3",
        from_version="1.26.0",
        to_version="1.26.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_BEHAVIOR,
            description="Dropped support for Python 3.6",
            old_api="Python 3.6 compatible",
            new_api="Python 3.7+ required",
            migration_guide="Upgrade to Python 3.7 or higher",
            source="known_breaking_changes",
        ),
    ),

    # httpx 0.23 -> 0.24+
    KnownBreakingChange(
        ecosystem=Ecosystem.PYPI,
        package="httpx",
        from_version="0.24.0",
        to_version="0.24.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_DEFAULT,
            description="Default timeout changed from 5s to no timeout",
            old_api="timeout=5.0 by default",
            new_api="timeout=None by default",
            migration_guide="Explicitly set timeout=httpx.Timeout(5.0) if needed",
            source="known_breaking_changes",
        ),
    ),

    # numpy 1.x -> 2.x
    KnownBreakingChange(
        ecosystem=Ecosystem.PYPI,
        package="numpy",
        from_version="2.0.0",
        to_version="2.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.REMOVED_FUNCTION,
            description="np.string_ and np.unicode_ aliases removed",
            old_api="np.string_, np.unicode_",
            new_api="np.bytes_, np.str_",
            migration_guide="Replace np.string_ with np.bytes_, np.unicode_ with np.str_",
            source="known_breaking_changes",
        ),
    ),
    KnownBreakingChange(
        ecosystem=Ecosystem.PYPI,
        package="numpy",
        from_version="2.0.0",
        to_version="2.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_BEHAVIOR,
            description="Copy semantics changed for array slicing",
            old_api="Slices sometimes share memory",
            new_api="More consistent copy-on-write semantics",
            migration_guide="Review code that relies on array view/copy behavior",
            source="known_breaking_changes",
        ),
    ),

    # pandas 1.x -> 2.x
    KnownBreakingChange(
        ecosystem=Ecosystem.PYPI,
        package="pandas",
        from_version="2.0.0",
        to_version="2.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_DEFAULT,
            description="Default datetime parsing changed, infer_datetime_format deprecated",
            old_api="infer_datetime_format=True",
            new_api="Use format='ISO8601' or format='mixed'",
            migration_guide="Explicitly specify date format in read_csv and to_datetime",
            source="known_breaking_changes",
        ),
    ),
    KnownBreakingChange(
        ecosystem=Ecosystem.PYPI,
        package="pandas",
        from_version="2.0.0",
        to_version="2.0.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_BEHAVIOR,
            description="Copy-on-Write (CoW) enabled by default in 3.0, opt-in in 2.x",
            old_api="In-place modifications affect views",
            new_api="CoW prevents accidental mutation of parent data",
            migration_guide="Enable CoW early with pd.options.mode.copy_on_write = True",
            source="known_breaking_changes",
        ),
    ),

    # aiohttp 3.8 -> 3.9
    KnownBreakingChange(
        ecosystem=Ecosystem.PYPI,
        package="aiohttp",
        from_version="3.9.0",
        to_version="3.9.0",
        change=BreakingChange(
            change_type=BreakingChangeType.CHANGED_DEFAULT,
            description="Dropped support for Python 3.7",
            old_api="Python 3.7 compatible",
            new_api="Python 3.8+ required",
            migration_guide="Upgrade to Python 3.8 or higher",
            source="known_breaking_changes",
        ),
    ),
]


def get_known_breaking_changes(
    ecosystem: Ecosystem,
    package_name: str,
    from_version: str,
    to_version: str,
) -> list[BreakingChange]:
    """Get known breaking changes for a package upgrade.

    Args:
        ecosystem: Package ecosystem.
        package_name: Package name (normalized).
        from_version: Starting version.
        to_version: Target version.

    Returns:
        List of known breaking changes.
    """
    import re

    def parse_version(v: str) -> tuple[int, ...]:
        """Parse version string to tuple."""
        parts = re.findall(r"\d+", v)
        return tuple(int(p) for p in parts[:3]) if parts else (0,)

    from_v = parse_version(from_version)
    to_v = parse_version(to_version)

    changes: list[BreakingChange] = []
    normalized_name = package_name.lower().replace("-", "_")

    for known in KNOWN_BREAKING_CHANGES:
        if known.ecosystem != ecosystem:
            continue

        known_name = known.package.lower().replace("-", "_")
        if known_name != normalized_name:
            continue

        # Check if the breaking change version is within our upgrade range
        change_v = parse_version(known.to_version)

        # Breaking change applies if: from_version < change_version <= to_version
        if from_v < change_v <= to_v:
            changes.append(known.change)

    return changes


def get_all_packages_with_known_changes() -> dict[Ecosystem, list[str]]:
    """Get all packages that have known breaking changes.

    Returns:
        Dictionary mapping ecosystem to list of package names.
    """
    packages: dict[Ecosystem, set[str]] = {}

    for known in KNOWN_BREAKING_CHANGES:
        if known.ecosystem not in packages:
            packages[known.ecosystem] = set()
        packages[known.ecosystem].add(known.package)

    return {eco: sorted(pkgs) for eco, pkgs in packages.items()}
