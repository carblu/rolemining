# Constrained Role Mining - UDCC Scenario
<p align="justify">
Role-based access control (RBAC) defines the methods complex organizations use to assign permissions for accessing resources to their users. RBAC assigns users to roles, and roles define the resources each user can access. Defining roles when there is a large number of users and many resources to handle could very hard. Hence, data mining techniques can be used to automatically propose candidate roles. The class of class of tools and methodologies to elicit roles starting from existing user-permission assignments are referred to as role mining. Sometime, to let the RBAC model directly deployable in organizations, role mining can also consider various constraints like cardinality and separation of duty. In general, constraints are enforced to easy roles’ management and their use is justified as role administration becomes convenient.
  </p>

<p align="justify">
We concentrate on the User-Distribution cardinality constraint. Such a constraint assumes that only a maximum number of users can be assigned a given role. In this scenario, we present a simple heuristic (<b>DuplicateUDCC</b>) that improves over the state of the art ones. Moreover, to consider a more realistic scenario, we propose to add another constraint to the User-Distribution model. Namely, we impose that the role mining procedure cannot generate two roles having the same set of permissions. We also describe a heuristic (<b>StrictUDCC</b>) to compute a solution in the new model. Heuristics' performances have been evaluated using real-world datasets. The Python code available in the folder <b>UDCC</b> implements both heuristics.
  </p>

<p align="justify">
The heuristic <b>StrictUDCC</b> has been tested using real-world datasets that were publicly available from HP labs
(A. Ene, W.G. Horne, N. Milosavljevic, P. Rao, R. Schreiber, and R.E. Tarjan <em>Fast exact and heuristic methods for role minimization problems</em>. ACM SACMAT 2008, pp. 1–10). Such datasets can also be found in the folder <b>datasets</b>.

The heuristics <b>DuplicateUDCC</b> and
</p>
