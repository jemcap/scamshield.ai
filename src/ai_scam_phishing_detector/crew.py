from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
from crewai.agents.agent_builder.base_agent import BaseAgent
from typing import List
# If you want to run a snippet of code before or after the crew starts,
# you can use the @before_kickoff and @after_kickoff decorators
# https://docs.crewai.com/concepts/crews#example-crew-class-with-decorators

@CrewBase
class AiScamPhishingDetector():
    """AiScamPhishingDetector crew"""

    agents: List[BaseAgent]
    tasks: List[Task]

    @agent
    def content_analyzer(self) -> Agent:
        return Agent(
            config=self.agents_config['content_analyzer'], # type: ignore[index]
            verbose=True
        )

    @agent
    def pattern_detector(self) -> Agent:
        return Agent(
            config=self.agents_config['pattern_detector'], # type: ignore[index]
            verbose=True
        )
    @agent
    def threat_assessor(self) -> Agent:
        return Agent(
            config=self.agents_config['threat_assessor'], # type: ignore[index]
            verbose=True
        )

    # To learn more about structured task outputs,
    # task dependencies, and task callbacks, check out the documentation:
    # https://docs.crewai.com/concepts/tasks#overview-of-a-task
    @task
    def analyze_content(self) -> Task:
        return Task(
            config=self.tasks_config['analyze_content'], # type: ignore[index]
        )

    @task
    def pattern_detection(self) -> Task:
        return Task(
            config=self.tasks_config['pattern_detection'], # type: ignore[index]
        )
    @task
    def threat_detection(self) -> Task:
        return Task(
            config=self.tasks_config['threat_detection'], # type: ignore[index]
        )

    @crew
    def crew(self) -> Crew:
        """Creates the AiScamPhishingDetector crew"""
        # To learn how to add knowledge sources to your crew, check out the documentation:
        # https://docs.crewai.com/concepts/knowledge#what-is-knowledge

        return Crew(
            agents=self.agents, # Automatically created by the @agent decorator
            tasks=self.tasks, # Automatically created by the @task decorator
            process=Process.sequential,
            verbose=True,
            # process=Process.hierarchical, # In case you wanna use that instead https://docs.crewai.com/how-to/Hierarchical/
        )
