from fastadmin.models.helpers import register_admin_model, unregister_admin_model
from tests.api.helpers import sign_in, sign_out


async def test_change(objects, client):
    superuser = objects["superuser"]
    event = objects["event"]
    admin_user_cls = objects["admin_user_cls"]
    admin_event_cls = objects["admin_event_cls"]
    await sign_in(client, superuser, admin_user_cls)
    register_admin_model(admin_event_cls, [event.__class__])
    r = await client.patch(
        f"/api/change/{event.__class__.__name__}/{event.id}",
        json={
            "name": "new name",
            "participants": [superuser.id],
        },
    )
    assert r.status_code == 200

    event = await event.__class__.get(id=event.id)
    item = r.json()
    assert item["id"] == event.id
    assert item["name"] == event.name
    assert item["tournament_id"] == event.tournament_id
    assert item["created_at"] == event.created_at.isoformat()
    assert item["updated_at"] == event.updated_at.isoformat()
    assert item["participants"] == [superuser.id]

    unregister_admin_model([event.__class__])
    await sign_out(client, superuser)


async def test_change_401(objects, client):
    superuser = objects["superuser"]
    event = objects["event"]
    r = await client.patch(
        f"/api/change/{event.__class__.__name__}/{event.id}",
        json={
            "name": "new name",
            "participants": [superuser.id],
        },
    )
    assert r.status_code == 401


async def test_change_404_admin_class_found(objects, client):
    superuser = objects["superuser"]
    event = objects["event"]
    admin_user_cls = objects["admin_user_cls"]
    await sign_in(client, superuser, admin_user_cls)
    r = await client.patch(
        f"/api/change/{event.__class__.__name__}/{event.id}",
        json={
            "name": "new name",
            "participants": [superuser.id],
        },
    )
    assert r.status_code == 404
    await sign_out(client, superuser)


async def test_change_404_obj_not_found(objects, client):
    superuser = objects["superuser"]
    event = objects["event"]
    admin_user_cls = objects["admin_user_cls"]
    admin_event_cls = objects["admin_event_cls"]
    await sign_in(client, superuser, admin_user_cls)
    register_admin_model(admin_event_cls, [event.__class__])
    r = await client.patch(
        f"/api/change/{event.__class__.__name__}/invalid",
        json={
            "name": "new name",
            "participants": [superuser.id],
        },
    )
    assert r.status_code == 422

    r = await client.patch(
        f"/api/change/{event.__class__.__name__}/-1",
        json={
            "name": "new name",
            "participants": [superuser.id],
        },
    )
    assert r.status_code == 404

    unregister_admin_model([event.__class__])
    await sign_out(client, superuser)